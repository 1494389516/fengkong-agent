# -*- coding: utf-8 -*-
"""规则试跑工具:对单个事件跑一遍规则集,返回命中规则与处置动作。

处置动作只有三档:pass < review < reject,多条规则命中时取最重的。
"""
from typing import Any, Dict, List, Optional

from . import tool
from .blacklist import blacklist_query
from .datasource import load_accounts
from .featurelib import account_features
from .intel import device_info
from .policy import active_policy

ACTION_ORDER = {"pass": 0, "review": 1, "reject": 2}
RULE_COUNT = 6  # 当前规则集条数,便于 agent 感知覆盖范围

# 阈值不再是本文件常量:全部经 policy.active_policy() 解析(版本化 + what-if
# 覆盖),定阈依据见 policy.DEFAULTS 的注释,数值回归见 eval 第 1 层。


def _blacklist_hit(dimension: str, value: str) -> bool:
    """名单联动取数:该维度值是否在黑/灰名单中。"""
    return blacklist_query(dimension, value)["hit"]


def _blacklist_records(dimension: str, value: str) -> List[Dict[str, Any]]:
    """名单联动取数:返回命中记录(含 list=black/gray 和 reason),未命中为空列表。"""
    return blacklist_query(dimension, value)["records"]


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
        "对一个事件试跑规则集,返回命中的规则列表和最终处置动作(pass/review/reject)。"
        "事件字段:uid(必填)、ip、device_id、type(如 login/order/coupon_claim)、"
        "amount、ts。带 ts 时默认完整回放:特征只用事件之前的数据,阈值用当时生效"
        "的策略版本(审计口径,'当时会怎么判');use_current_policy=true 则改用当前"
        "最新阈值评估该事件('现在会怎么判'),特征仍按事件时点取证。"
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
    for dim, val in (("uid", uid), ("ip", ip), ("device_id", device_id)):
        if not val:
            continue
        for rec in _blacklist_records(dim, val):
            action = "reject" if rec["list"] == "black" else "review"
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
        gap = feats.get("min_gap_seconds")
        # 特征按 ts < as_of 取证(防泄漏),不含当前被评估事件;但"第 N 次领券"
        # 的计数必须含当次 —— 生产引擎在第 N 次到达时就计数并拦截,而回放里
        # feats 只数到 N-1,strict 比较让实际生效阈值变成 N+1:恰好刷满阈值的
        # bot 会在回放里漏过、与生产结论分歧。当次即一次 coupon_claim,+1 对齐。
        count = feats["event_count"] + 1
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

    action = "pass"
    for h in hits:
        if ACTION_ORDER.get(h["action"], 0) > ACTION_ORDER[action]:
            action = h["action"]
    return {
        "hits": hits,
        "action": action,
        "rule_count_evaluated": RULE_COUNT,
        "policy_version": p["_version"],
        "policy_overridden": p["_overridden"],
        "features_snapshot": feats,
    }
