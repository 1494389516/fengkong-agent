# -*- coding: utf-8 -*-
"""策略(阈值)版本单点:阈值从代码常量变为带版本的配置。

为什么要版本化(与特征 as-of 同构):
- 审计:历史处置必须能回放"当时生效的阈值";配置只留最新版等于历史被覆写。
- 对抗:任何自动重校准的基线都是攻击面("养基线"),所以校准只产提案,
  生效必须走 actions.py 两阶段人工审批,且单参数变幅限速(MAX_CHANGE_RATIO)。
- 反馈回路:新旧策略的差异用影子回测(backtest.shadow_compare)看,不直接切换。

解析优先级:what-if 覆盖 > 按 as_of 选中的版本 values > DEFAULTS。
覆盖无视 as_of 生效(否则 what-if 在带 ts 的事件上不起作用)。
文件缺失、或 as_of 早于所有版本 effective_from 时,回退 DEFAULTS(隐式 v0)
—— 样本/生成数据的事件 ts 都在过去,仓库 v1 的 effective_from 因此取 0。

工程约束:
- 路径每次经 datasource 解析(FK_DATA_DIR/FK_DATASET 可切),读缓存复用
  datasource 的 (path, mtime) 机制,本模块不得另设缓存(会串数据集),
  也不得缓存"文件不存在"(审批新建文件后同进程要立刻读到)。
- 模块级依赖只允许 stdlib + datasource:rules 每事件热路径经过这里,禁 pandas。
"""
import contextvars
import time
from typing import Any, Dict, List, Optional, Tuple

from . import tool
from .datasource import _load_json, atomic_write_json, file_lock, thresholds_path

# 全部阈值的缺省值(隐式 v0)。注释保留原 rules/monitor 的定阈依据。
# 值以数值为主;decision_combine 是枚举字面量(见 ENUM_KEYS),不当数字限速。
DEFAULTS: Dict[str, Any] = {
    # R002:样本机器人 gap=3s/20 次,正常最快 300s/6 次,带宽很大取偏严一侧
    "r002_max_gap_seconds": 30,   # 人手连点很难稳定低于 30s
    "r002_min_events": 10,        # 次数下限,偶发快速操作不触发
    "r002_reject_min_ips": 3,     # 高频 + 多 IP 轮换基本排除人类,升级 reject
    # R003
    "r003_high_amount": 1000.0,       # 大额订单:金额越大,销赃收益越高
    "r003_cashout_max_amount": 20.0,  # 小额套现:金额本身无害,须叠加领券信号
    "r003_cashout_min_coupons": 3,
    "r003_cashout_window_seconds": 3600,  # 会话口径:领券->下单 1 小时内才算套现模式
    # R004 账龄错配:新号做老号的事。信任要靠时间积累,攻击者最缺的就是时间
    "r004_max_account_age_seconds": 604800,  # 注册 7 天内算新号
    "r004_min_amount": 200.0,                # 新号订单金额下限,低于此不值得看
    # R005 高危注册 × 新号交易:注册风险分(生产注册风控的历史打分)高的新号下单
    "r005_min_register_score": 70,
    "r005_max_account_age_seconds": 604800,
    # R006 设备指纹硬拦截开关(1=强拒 0=关闭):业务拍板"模拟器/root/hook 一律拒",
    # 已知误伤面(root 真机极客、PC 模拟器真实玩家)由申诉通道兜底;
    # 开关型参数不适用 ±50% 比例限速(threshold_propose 有豁免)
    "r006_reject_emulator": 1,
    "r006_reject_rooted": 1,
    "r006_reject_hook": 1,
    # 监控窗口信号(与 R002 分开:监控偏灵敏、规则偏保守)
    "geo_jump_speed_kmh": 900.0,  # 超过民航巡航速度的"移动"= 物理不可能
    "monitor_burst_min": 8,
    "monitor_ip_churn_min": 3,
    "monitor_rapid_gap_seconds": 5,
    "monitor_rapid_min_events": 3,
    "shared_device_min_accounts": 3,
    # 模拟一致性:本地模拟与生产决策日志的不一致率超过此值即"模拟器失信",
    # 回测/影子/校准类结论自动降级(reconcile.py)
    "max_sim_mismatch_rate": 0.02,
    # 自身基线(账龄门槛防"养基线":新号/低历史账号不享受自身基线特权)
    "self_min_history_events": 5,
    "self_recent_window_seconds": 86400,
    "self_amount_spike_ratio": 3.0,
    "self_amount_floor": 100.0,
    # 灰名单生命周期:灰是观察态,必须走向结论(升黑/出灰),不能永久挂着
    "graylist_observe_days": 30,        # 默认观察期:期满且干净建议出灰
    "graylist_promote_min_review": 3,   # 关联账号中 >= N 个命中 review 即聚集性实锤,建议升黑
    # R007 模型信号(引擎层规则):champion 模型风险分(0~1,越大越可疑)过线
    # 即命中。默认 0.9/0.98 是"关着"的阈值 —— 模型要真正生效必须走
    # threshold_propose 调低(与规则阈值同级治理、可审批可回滚),不是部署
    # champion 就自动拦截:上线动作与生效力度是两件事,各自留痕。
    "model_score_review_threshold": 0.90,
    "model_score_reject_threshold": 0.98,
    # 多规则合成(coolGuard 编排):hits 仍全算全留,变的是 action 怎么从 hits
    # 长出来。默认 worst=现口径(多规则取最重),换模式与阈值同级治理。
    "decision_combine": "worst",
    "r001_weight": 1.0,
    "r002_weight": 1.0,
    "r003_weight": 1.0,
    "r004_weight": 1.0,
    "r005_weight": 1.0,
    "r006_weight": 1.0,
    "r007_weight": 1.0,
    "combine_weight_review": 1.0,   # weight 模式:score >= 此值 → review
    "combine_weight_reject": 2.0,   # weight 模式:score >= 此值 → reject
}

# rule_backtest / chart_threshold_sweep 允许覆盖的键(规则组)。
# monitor_*/self_* 不在此列:回测不跑监控,覆盖它们只会误导。
RULE_KEYS = ("r002_max_gap_seconds", "r002_min_events", "r002_reject_min_ips",
             "r003_high_amount", "r003_cashout_max_amount",
             "r003_cashout_min_coupons", "r003_cashout_window_seconds",
             "r004_max_account_age_seconds", "r004_min_amount",
             "r005_min_register_score", "r005_max_account_age_seconds",
             "r006_reject_emulator", "r006_reject_rooted", "r006_reject_hook",
             "model_score_review_threshold", "model_score_reject_threshold",
             "r001_weight", "r002_weight", "r003_weight", "r004_weight",
             "r005_weight", "r006_weight", "r007_weight",
             "combine_weight_review", "combine_weight_reject")

# 开关型参数(取值只允许 0/1):强拒开/关。显式声明而非按值域猜"是不是开关"
# —— 按 {现值,新值}⊆{0,1} 推断会把恰好取 0/1 的数值参数误判成开关而豁免限速,
# 也会放过 0.5 这种"既非开也非关"的非法值。限速对开关无意义(1->0 变幅 100%),
# 但要卡死取值域只能 0/1。
SWITCH_KEYS = ("r006_reject_emulator", "r006_reject_rooted", "r006_reject_hook")

# 枚举型参数:取值是字面量不是数。±50% 限速无意义(worst→vote 不是"变了 100%"),
# 但要卡死取值域。与 SWITCH_KEYS 同级 —— 显式声明,不按类型猜。
# decision_combine 不进 RULE_KEYS:阈值扫描扫字符串无意义。
ENUM_KEYS = {
    "decision_combine": ("worst", "sequential", "vote", "weight"),
}

# 影子回测/what-if 可覆盖:规则数值 + 枚举编排。阈值扫描只扫 SWEEPABLE
# (字符串扫图无意义),但 decision_combine 必须能进 shadow_compare。
OVERRIDABLE: Tuple[str, ...] = RULE_KEYS + tuple(ENUM_KEYS)
SWEEPABLE: Tuple[str, ...] = RULE_KEYS

MAX_CHANGE_RATIO = 0.5  # 提案限速:单参数变幅超 ±50% 拒绝,防一次校准被极端数据带飞

# what-if 覆盖用 ContextVar:serve 多线程 + job 后台线程不能共享一份全局 dict。
_overrides_var: contextvars.ContextVar[Dict[str, Any]] = contextvars.ContextVar(
    "fk_overrides", default=None)
_enabled_rules_var: contextvars.ContextVar[Optional[Tuple[str, ...]]] = (
    contextvars.ContextVar("fk_enabled_rules", default=None))


def _overrides() -> Dict[str, Any]:
    cur = _overrides_var.get()
    return cur if cur is not None else {}


def _versions() -> List[Dict]:
    try:
        raw = _load_json(thresholds_path())
    except FileNotFoundError:
        return []
    return sorted(raw, key=lambda v: (v["effective_from"], v["version"]))


def active_policy(as_of_ts: Optional[float] = None) -> Dict:
    """解析某时点生效的全量阈值。as_of_ts=None 表示当前最新。
    返回 dict 额外带 _version(0=纯 DEFAULTS)与 _overridden 元信息。"""
    p: Dict = dict(DEFAULTS)
    p["_version"] = 0
    for v in _versions():  # 升序累积:每个版本的 values 是相对前版的变更集
        if as_of_ts is None or v["effective_from"] <= as_of_ts:
            p.update(v["values"])
            p["_version"] = v["version"]
    ov = _overrides()
    p["_overridden"] = bool(ov)
    p.update(ov)
    return p


def snapshot_at_version(version: int) -> Dict[str, Any]:
    """重建策略版本表在 version N 时的完整快照(DEFAULTS ⊕ v1…vN 累积)。
    回放不能只取 vN 的 delta,否则会漏掉中间版本已生效的键。"""
    versions = _versions()
    snap = dict(DEFAULTS)
    found = False
    for v in versions:
        snap.update(v.get("values") or {})
        if v.get("version") == version:
            found = True
            break
    if not found:
        raise ValueError("策略版本不存在: v%d" % version)
    return {k: snap[k] for k in DEFAULTS}


def set_overrides(overrides: Dict) -> Dict:
    """what-if 覆盖:先全量校验、后原子应用 —— 部分应用会把错误值泄漏给
    进程内后续所有调用(迁移前的 backtest 实有此 bug)。返回旧覆盖快照,
    调用方必须在 finally 里 restore_overrides(快照),不许无条件清空
    (否则嵌套调用会把外层覆盖清掉)。"""
    bad = [k for k in overrides if k not in DEFAULTS]
    if bad:
        raise ValueError("未知阈值参数: %s" % ", ".join(bad))
    prev = dict(_overrides())
    _overrides_var.set(dict(overrides))
    return prev


def restore_overrides(prev: Dict) -> None:
    _overrides_var.set(dict(prev))


def set_enabled_rules(rules: Optional[List[str]]) -> Optional[Tuple[str, ...]]:
    """策略规则集覆盖:非空 = 只启用这些规则;空/None = 全开(未声明)。"""
    prev = _enabled_rules_var.get()
    if rules:
        _enabled_rules_var.set(tuple(rules))
    else:
        _enabled_rules_var.set(None)
    return prev


def restore_enabled_rules(prev: Optional[Tuple[str, ...]]) -> None:
    _enabled_rules_var.set(prev)


def enabled_rules() -> Optional[Tuple[str, ...]]:
    return _enabled_rules_var.get()


def overrides_key():
    """当前 what-if 覆盖的指纹(排序元组)。判定缓存的 key 组成部分:
    覆盖生效期间的结果不能和无覆盖的混用。"""
    return tuple(sorted(_overrides().items()))


def latest_baseline_snapshot():
    """最近一个带基线快照的版本,漂移告警的参照。(版本号, 快照) 或 (None, None)。"""
    for v in reversed(_versions()):
        if v.get("baseline_snapshot"):
            return v["version"], v["baseline_snapshot"]
    return None, None


def apply_change(action: Dict, approved_by: str = "cli") -> Dict:
    """actions.decide 批准 threshold_change 后调用:追加新版本并落盘。
    顺带记录批准时刻的人群基线快照,作为未来漂移告警的参照。"""
    snap = None
    try:
        from .featurelib import population_baseline  # 惰性:数据缺失不阻塞审批
        snap = population_baseline()
    except Exception:  # noqa: BLE001
        snap = None
    path = thresholds_path()
    with file_lock(path):
        versions = _versions()
        entry = {
            "version": max((v["version"] for v in versions), default=0) + 1,
            "effective_from": int(time.time()),
            "approved_by": approved_by,
            "note": action.get("reason", ""),
            "values": action["values"],
        }
        if snap:
            entry["baseline_snapshot"] = snap
        versions.append(entry)
        atomic_write_json(path, versions)
    return entry


@tool(
    name="policy_history",
    description=(
        "列出阈值策略的全部版本:版本号、生效时间、审批人、变更内容、说明。"
        "回答'这条阈值什么时候改的''当时生效的是哪版策略'类审计问题用。"
        "rule_eval 默认按事件 ts 回放当时版本,二者配合可完整复现历史处置。"
    ),
    parameters={"type": "object", "properties": {}},
)
def policy_history():
    versions = _versions()
    return {
        "versions": [{k: v.get(k) for k in ("version", "effective_from", "approved_by", "note", "values")}
                     for v in versions],
        "active_version": active_policy()["_version"],
        "defaults_in_use": not versions,
    }
