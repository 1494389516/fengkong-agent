# -*- coding: utf-8 -*-
"""规则试跑工具:对单个事件跑一遍规则集,返回命中规则与处置动作。

处置动作只有三档:pass < review < reject,多条规则命中时取最重的。
"""
from typing import Any, Dict, List, Optional

from . import tool
from .blacklist import active_records
from .datasource import load_accounts
from .featurelib import account_features
from .intel import device_info
from .policy import active_policy

ACTION_ORDER = {"pass": 0, "review": 1, "reject": 2}
RULE_COUNT = 6  # 当前规则集条数,便于 agent 感知覆盖范围

# 阈值不再是本文件常量:全部经 policy.active_policy() 解析(版本化 + what-if
# 覆盖),定阈依据见 policy.DEFAULTS 的注释,数值回归见 eval 第 1 层。


def _blacklist_records(dimension: str, value: str,
                       as_of_ts: Any = None) -> List[Dict[str, Any]]:
    """R001 口径:黑/灰记录(白名单不进 R001,是反方向的抑制层),按事件时点过滤有效期。"""
    return active_records(dimension, value, as_of_ts, lists=("black", "gray"))


def _apply_whitelist(hits: List[Dict[str, str]], white: List[Dict],
                     conflict: bool) -> None:
    """白名单 = 全体命中降一档(就地修改):reject 级证据降为 review(白名单
    账号被盗/被收买是真实攻击路径,人工闸门不能撤),review 级证据抑制为
    pass(误伤抑制的本职)。绝不是免死金牌。conflict(同值既黑又白)时
    以黑为准、白名单整体失效,只留告警 —— 名单打架是数据治理问题,
    不能让规则引擎替人裁决。"""
    if not white or conflict:
        return
    for h in hits:
        new_action = "review" if h["action"] == "reject" else "pass"
        if ACTION_ORDER[new_action] < ACTION_ORDER[h["action"]]:
            h["original_action"] = h["action"]
            h["action"] = new_action
            h["whitelisted"] = True


def _uid_features(uid: str, as_of_ts: Optional[float] = None,
                  window_seconds: Optional[int] = None):
    """特征联动取数:返回 uid 的行为特征 dict,无数据时返回 None。
    as_of_ts = 被评估事件的 ts —— 只用事件之前的历史(point-in-time),
    否则特征会偷看未来,回测虚高、线上对不上。"""
    r = account_features(uid, as_of_ts, window_seconds)
    return r if r.get("found") else None


def _hit(hits: List[Dict[str, str]], rule_id: str, reason: str, action: str) -> None:
    """追加一条命中记录。action 必须是 pass/review/reject 之一。"""
    hits.append({"rule_id": rule_id, "reason": reason, "action": action})


@tool(
    name="rule_eval",
    description=(
        "对一个事件试跑规则集,返回命中规则与最终处置(pass/review/reject)。"
        "事件字段:uid(必填)、ip、device_id、type、amount、ts。带 ts 默认完整"
        "回放(当时的特征 + 当时的策略版本,审计口径);use_current_policy=true "
        "用当前最新阈值('现在会怎么判'),特征仍按事件时点。白名单命中降一档"
        "(hits 保留 original_action);黑白冲突返回 whitelist_conflict;"
        "灰名单+行为命中返回 gray_escalation_hint。"
        "判定来源看返回的 source 字段:生产引擎 dry-run 优先(engine_status 查"
        "当前通道),本地 R001-R006 只是降级备份;degraded=true 时必须声明"
        "本判定为本地备份结论。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "event": {
                "type": "object",
                "description": "待评估事件",
                "properties": {
                    "uid": {"type": "string"},
                    "ip": {"type": "string"},
                    "device_id": {"type": "string"},
                    "type": {"type": "string", "description": "事件类型"},
                    "amount": {"type": "number", "description": "金额,可选"},
                    "ts": {"type": "number", "description": "事件时间戳(unix 秒),可选"},
                },
                "required": ["uid"],
            },
            "use_current_policy": {
                "type": "boolean",
                "description": "true=用当前最新阈值评估(默认 false=回放事件当时的阈值版本)",
            },
        },
        "required": ["event"],
    },
)
def rule_eval(event: Dict[str, Any], use_current_policy: bool = False):
    """规则试跑:判定唯一入口在 agent.engine —— 生产引擎 dry-run 优先,
    本地实现是降级备份。返回带 source 字段(local_rules / remote_engine /
    local_rules_fallback)。"""
    from ..engine import evaluate_event
    return evaluate_event(event, use_current_policy=use_current_policy)


def _local_rule_eval(event: Dict[str, Any], use_current_policy: bool = False):
    """本地 R001-R006 实现 —— 骨架替身/降级备份,不是独立引擎。
    公开判定入口是 agent.engine.evaluate_event(经上方的 rule_eval 工具)。"""
    hits: List[Dict[str, str]] = []
    uid = event.get("uid", "")
    ip = event.get("ip", "")
    device_id = event.get("device_id", "")
    event_type = event.get("type", "")
    amount = event.get("amount")
    # 特征口径:事件带 ts 时永远以事件时点取证(防泄漏),与策略口径无关
    as_of = event.get("ts")
    feats = _uid_features(uid, as_of)
    # 策略口径:默认回放当时生效的版本(审计);backtest/scan 传 use_current_policy=True
    # 用当前策略评估历史数据 —— 否则批准了新版本,回测指标永远照不进
    p = active_policy(None if use_current_policy else as_of)

    # ------------------------------------------------------------------
    # R001 名单硬拦截:uid / ip / device_id 三个维度带值的全查。
    # black 是人工确认过的(盗号工单、代理池),直接 reject;
    # gray 只是设备指纹嫌疑(模拟器上也有正常用户),给 review 留人工兜底
    # —— 误伤代价是真实模拟器用户多走一道审核,可接受。
    # ------------------------------------------------------------------
    # 白名单联动(误伤抑制层,评估在所有规则之后):收集三维度的有效白记录;
    # 同一值既黑又白 = 名单冲突,白名单失效以黑为准(数据治理告警)
    white: List[Dict[str, Any]] = []
    white_conflict = False
    for dim, val in (("uid", uid), ("ip", ip), ("device_id", device_id)):
        if not val:
            continue
        for rec in active_records(dim, val, as_of, lists=("white",)):
            white.append({"dimension": dim, "value": val, "reason": rec["reason"],
                          "expires_at": rec.get("expires_at")})
            if active_records(dim, val, as_of, lists=("black",)):
                white_conflict = True

    gray_hit = False
    for dim, val in (("uid", uid), ("ip", ip), ("device_id", device_id)):
        if not val:
            continue
        for rec in _blacklist_records(dim, val, as_of):
            action = "reject" if rec["list"] == "black" else "review"
            gray_hit = gray_hit or rec["list"] == "gray"
            _hit(hits, "R001", "%s=%s 命中%s名单: %s" % (dim, val, rec["list"], rec["reason"]), action)

    # ------------------------------------------------------------------
    # R006 设备指纹硬拦截:模拟器 / root / hook 一律 reject(业务拍板的强硬
    # 策略)。指纹是设备指纹 SDK 实时采集的物理事实,不依赖行为历史 ——
    # 与名单的区别:名单要人工添加,指纹到即拦。三个开关独立进 policy
    # (1=强拒 0=关闭),降级为 review 走提案审批改开关即可。
    # 已知误伤面(留档):root 真机有极客真实用户、模拟器有 PC 端真实玩家,
    # 强拒是拦截收益 > 误伤代价的业务取舍,误伤走申诉通道;
    # 关掉某开关的影响用 shadow_backtest 覆盖 r006_reject_rooted=0 量化。
    # ------------------------------------------------------------------
    if device_id:
        dinfo = device_info(device_id)
        fp_hits = []
        if p["r006_reject_emulator"] and dinfo.get("is_emulator"):
            fp_hits.append("模拟器" + ("(%s)" % dinfo["emulator_brand"]
                                       if dinfo.get("emulator_brand") else ""))
        if p["r006_reject_rooted"] and dinfo.get("is_rooted"):
            fp_hits.append("root")
        if p["r006_reject_hook"] and dinfo.get("hook_detected"):
            fp_hits.append("hook 注入")
        if fp_hits:
            _hit(hits, "R006", "设备 %s 指纹命中: %s" % (device_id, "、".join(fp_hits)), "reject")

    # ------------------------------------------------------------------
    # R002 机器行为 / 频率异常:目前只对 coupon_claim 生效(样本攻击面在
    # 刷券;扩到 login/order 需按事件类型分别定阈值,不能共用)。
    # 间隔 + 次数双条件防误伤:单独手快或偶发连点都不触发。
    # 高频之上再叠加多 IP 轮换时升级 reject —— 单纯高频最多 review,
    # 因为极端活跃的真人无法完全排除,而"高频 + 换 IP"基本只能是脚本。
    # ------------------------------------------------------------------
    if feats and event_type == "coupon_claim":
        # 间隔与计数都必须是领券口径:全事件流的 event_count/min_gap 会把
        # "登录多、下单快"的活跃正常账号当成刷券 bot(实锤误伤过,见 backtest
        # 的 R002 fp),证据文案里的"领券 N 次"也会变成编造数字。
        gap = feats.get("coupon_min_gap_seconds")
        # 特征按 ts < as_of 取证(防泄漏),不含当前被评估事件;但"第 N 次领券"
        # 的计数必须含当次 —— 生产引擎在第 N 次到达时就计数并拦截,而回放里
        # feats 只数到 N-1,strict 比较让实际生效阈值变成 N+1:恰好刷满阈值的
        # bot 会在回放里漏过、与生产结论分歧。当次即一次 coupon_claim,+1 对齐。
        count = feats["coupon_claims"] + 1
        if gap is not None and gap <= p["r002_max_gap_seconds"] and count >= p["r002_min_events"]:
            action = "reject" if feats["distinct_ip"] >= p["r002_reject_min_ips"] else "review"
            _hit(hits, "R002", "领券最短间隔 %ds,累计 %d 次,涉及 %d 个 IP" % (
                gap, count, feats["distinct_ip"]), action)

    # ------------------------------------------------------------------
    # R003 金额异常,两个互斥分支:
    # 大额(>= 1000):销赃收益高,但正常大单也存在,单金额只到 review;
    #   要不要 reject 交给名单/行为规则叠加决定(u_1009 即由 R001 升到 reject)。
    # 小额套现(<= 20):9.9 本身无害,必须叠加"下单前 1 小时窗口内领券 >= 3 次"
    #   的会话信号才 review —— 窗口口径,不是全历史计数(见常量处的实锤教训)。
    # 非 order 或未带 amount 的事件不评估。
    # ------------------------------------------------------------------
    # reason 文案里的阈值必须读同一份 p:override/版本生效时,证据链数字要和实际判定一致
    if event_type == "order" and amount is not None:
        if amount >= p["r003_high_amount"]:
            _hit(hits, "R003", "订单金额 %.2f 达到大额阈值 %.0f" % (amount, p["r003_high_amount"]), "review")
        elif amount <= p["r003_cashout_max_amount"]:
            wf = _uid_features(uid, as_of, int(p["r003_cashout_window_seconds"]))
            coupons = wf["coupon_claims"] if wf else 0
            if coupons >= p["r003_cashout_min_coupons"]:
                _hit(hits, "R003", "下单前 %d 分钟内领券 %d 次后下小额订单 %.2f,疑似领券套现"
                     % (int(p["r003_cashout_window_seconds"]) // 60, coupons, amount), "review")

    # ------------------------------------------------------------------
    # R004 新号大额 / R005 高危注册 × 新号交易 —— 两条"出生证明"规则。
    # 共同前提:order 事件 + 带 ts(账龄=事件 ts-注册时间,无时点不评估)+
    # 有主档(缺失在生产上应告警,骨架从简跳过)。都给 review:可能是真实
    # 新客首单,误伤代价高,留人工兜底。
    # R004 看行为错配(注册没几天就下大额单,信任要靠时间积累);
    # R005 消费注册风险分 —— 分数是生产注册风控在注册时刻打的历史事实,
    #   agent 只读不重算(唯一事实源,口径核验在 reconcile 的主档对账);
    #   高分不拦零成本动作(领券留给行为规则),只在有资损的下单环节加闸。
    # ------------------------------------------------------------------
    if event_type == "order" and amount is not None and as_of is not None:
        acct = load_accounts().get(uid)
        if acct:
            age = as_of - acct["registered_at"]
            if amount >= p["r004_min_amount"] and 0 <= age <= p["r004_max_account_age_seconds"]:
                _hit(hits, "R004", "注册仅 %.1f 小时即下单 %.2f(新号大额)"
                     % (age / 3600, amount), "review")
            score = acct.get("register_risk_score")
            if (score is not None and score >= p["r005_min_register_score"]
                    and 0 <= age <= p["r005_max_account_age_seconds"]):
                _hit(hits, "R005", "注册风险分 %d(阈值 %d)的新号下单 %.2f,账龄 %.1f 小时"
                     % (score, p["r005_min_register_score"], amount, age / 3600), "review")

    _apply_whitelist(hits, white, white_conflict)

    action = "pass"
    for h in hits:
        if ACTION_ORDER.get(h["action"], 0) > ACTION_ORDER[action]:
            action = h["action"]
    result = {
        "hits": hits,
        "action": action,
        "rule_count_evaluated": RULE_COUNT,
        "policy_version": p["_version"],
        "policy_overridden": p["_overridden"],
        "features_snapshot": feats,
    }
    if white:
        result["whitelist"] = {"records": white, "applied": not white_conflict}
        if white_conflict:
            result["whitelist_conflict"] = (
                "名单冲突:同一值同时在黑名单与白名单,已以黑为准、白名单失效 —— "
                "请先修复名单数据(这是治理问题,规则引擎不替人裁决)")
    # 灰名单联动:嫌疑资源上又出现行为规则命中 = 双重证据。处置动作不在此升级
    # (保守),但给出升黑评估提示 —— 结论走 graylist_review 的证据化裁决
    if gray_hit and any(h["rule_id"] != "R001"
                        and ACTION_ORDER.get(h.get("original_action", h["action"]), 0) >= 1
                        for h in hits):
        result["gray_escalation_hint"] = (
            "灰名单资源 + 行为规则命中(双重证据):建议跑 graylist_review 评估升黑")
    return result
