# -*- coding: utf-8 -*-
"""规则试跑工具:对单个事件跑一遍规则集,返回命中规则与处置动作。

处置动作只有三档:pass < review < reject,多条规则命中时取最重的。
"""
from typing import Any, Dict, List, Optional

from . import tool
from .blacklist import blacklist_query
from .featurelib import account_features

ACTION_ORDER = {"pass": 0, "review": 1, "reject": 2}
RULE_COUNT = 3  # 当前规则集条数,便于 agent 感知覆盖范围

# R002 阈值:样本里机器人 gap=3s/20 次,正常用户最快 gap=300s/6 次,中间带很宽,
# 阈值取在带内偏严一侧,改动时用 eval/run_eval.py 第 1 层回归。
R002_MAX_GAP_SECONDS = 30  # 人手连点很难稳定低于 30s 间隔,留了极端活跃用户余量
R002_MIN_EVENTS = 10       # 次数下限:偶发快速操作(连领两三张券)不触发
R002_REJECT_MIN_IPS = 3    # 高频之上再叠加多 IP 轮换,基本可排除人类,升级 reject

# R003 阈值
R003_HIGH_AMOUNT = 1000.0       # 大额订单:金额越大,盗号销赃收益越高
R003_CASHOUT_MAX_AMOUNT = 20.0  # 小额套现:金额本身无害,必须叠加领券行为信号
R003_CASHOUT_MIN_COUPONS = 3
# 套现的领券计数只看下单前这个窗口内的(会话口径)。全历史计数曾在生成
# 大样本上实锤误伤:一周攒 3 张券又碰巧买便宜货的正常用户会被扫进来。
# 1 小时能覆盖"领券->凑单->下单"的完整会话,又不会把隔天行为串起来。
R003_CASHOUT_WINDOW_SECONDS = 3600


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
        "事件字段:uid(必填)、ip、device_id、type(如 login/order/coupon_claim)、amount。"
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
                },
                "required": ["uid"],
            },
        },
        "required": ["event"],
    },
)
def rule_eval(event: Dict[str, Any]):
    hits: List[Dict[str, str]] = []
    uid = event.get("uid", "")
    ip = event.get("ip", "")
    device_id = event.get("device_id", "")
    event_type = event.get("type", "")
    amount = event.get("amount")
    # 事件带 ts 时以事件时点取证(point-in-time);不带 ts(假设性咨询)用全历史
    as_of = event.get("ts")
    feats = _uid_features(uid, as_of)

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
    # R002 机器行为 / 频率异常:目前只对 coupon_claim 生效(样本攻击面在
    # 刷券;扩到 login/order 需按事件类型分别定阈值,不能共用)。
    # 间隔 + 次数双条件防误伤:单独手快或偶发连点都不触发。
    # 高频之上再叠加多 IP 轮换时升级 reject —— 单纯高频最多 review,
    # 因为极端活跃的真人无法完全排除,而"高频 + 换 IP"基本只能是脚本。
    # ------------------------------------------------------------------
    if feats and event_type == "coupon_claim":
        gap = feats.get("min_gap_seconds")
        if gap is not None and gap <= R002_MAX_GAP_SECONDS and feats["event_count"] >= R002_MIN_EVENTS:
            action = "reject" if feats["distinct_ip"] >= R002_REJECT_MIN_IPS else "review"
            _hit(hits, "R002", "领券最短间隔 %ds,累计 %d 次,涉及 %d 个 IP" % (
                gap, feats["event_count"], feats["distinct_ip"]), action)

    # ------------------------------------------------------------------
    # R003 金额异常,两个互斥分支:
    # 大额(>= 1000):销赃收益高,但正常大单也存在,单金额只到 review;
    #   要不要 reject 交给名单/行为规则叠加决定(u_1009 即由 R001 升到 reject)。
    # 小额套现(<= 20):9.9 本身无害,必须叠加"下单前 1 小时窗口内领券 >= 3 次"
    #   的会话信号才 review —— 窗口口径,不是全历史计数(见常量处的实锤教训)。
    # 非 order 或未带 amount 的事件不评估。
    # ------------------------------------------------------------------
    if event_type == "order" and amount is not None:
        if amount >= R003_HIGH_AMOUNT:
            _hit(hits, "R003", "订单金额 %.2f 达到大额阈值 %.0f" % (amount, R003_HIGH_AMOUNT), "review")
        elif amount <= R003_CASHOUT_MAX_AMOUNT:
            wf = _uid_features(uid, as_of, R003_CASHOUT_WINDOW_SECONDS)
            coupons = wf["coupon_claims"] if wf else 0
            if coupons >= R003_CASHOUT_MIN_COUPONS:
                _hit(hits, "R003", "下单前 %d 分钟内领券 %d 次后下小额订单 %.2f,疑似领券套现"
                     % (R003_CASHOUT_WINDOW_SECONDS // 60, coupons, amount), "review")

    action = "pass"
    for h in hits:
        if ACTION_ORDER.get(h["action"], 0) > ACTION_ORDER[action]:
            action = h["action"]
    return {
        "hits": hits,
        "action": action,
        "rule_count_evaluated": RULE_COUNT,
        "features_snapshot": feats,
    }
