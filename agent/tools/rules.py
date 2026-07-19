# -*- coding: utf-8 -*-
"""规则试跑工具:对单个事件跑一遍规则集,返回命中规则与处置动作。

处置动作只有三档:pass < review < reject,多条规则命中时取最重的。
"""
from typing import Any, Dict, List

from . import tool
from .blacklist import blacklist_query
from .features import feature_stats

ACTION_ORDER = {"pass": 0, "review": 1, "reject": 2}
RULE_COUNT = 3  # 当前规则集条数,便于 agent 感知覆盖范围


def _blacklist_hit(dimension: str, value: str) -> bool:
    """名单联动取数:该维度值是否在黑/灰名单中。"""
    return blacklist_query(dimension, value)["hit"]


def _blacklist_records(dimension: str, value: str) -> List[Dict[str, Any]]:
    """名单联动取数:返回命中记录(含 list=black/gray 和 reason),未命中为空列表。"""
    return blacklist_query(dimension, value)["records"]


def _uid_features(uid: str):
    """特征联动取数:返回 uid 的行为特征 dict,无数据时返回 None。"""
    r = feature_stats(uid)
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
    feats = _uid_features(uid)

    # ------------------------------------------------------------------
    # R001 名单硬拦截
    #
    # 样本线索:
    #   u_1009 + ip 203.0.113.66 → 黑名单, reason 含「代理池/盗号」
    #   dev_emu_9f3a → 灰名单(模拟器)
    #
    # 你要决定:
    #   - 只拦 black,还是 gray 也要管?
    #   - black 给 reject,gray 给 review 还是也 reject?
    #   - 查哪些维度:uid / ip / device_id 全查还是只查部分?
    # ------------------------------------------------------------------
    # TODO: 实现 R001
    #
    # 提示写法(按需删改):
    # for dim, val in [("uid", uid), ("ip", ip), ("device_id", device_id)]:
    #     if not val:
    #         continue
    #     for rec in _blacklist_records(dim, val):
    #         action = "reject" if rec["list"] == "black" else "review"
    #         _hit(hits, "R001", "%s=%s 命中%s名单: %s" % (dim, val, rec["list"], rec["reason"]), action)

    # ------------------------------------------------------------------
    # R002 机器行为 / 频率异常
    #
    # 样本线索:
    #   u_1002 → event_count=20, min_gap_seconds=3, distinct_ip=5, 全是 coupon_claim
    #   u_1001 → event_count=5,  min_gap_seconds=300, 正常用户对照组
    #
    # 你要决定:
    #   - min_gap_seconds 阈值设多少?(3 秒很极端,300 秒就宽松很多)
    #   - 要不要叠加 event_count 下限,避免偶发快速操作误伤?
    #   - 是否限定 event_type == "coupon_claim"?
    #   - 命中给 review 还是 reject?
    # ------------------------------------------------------------------
    # TODO: 实现 R002
    #
    # 提示写法(按需删改):
    # if feats and event_type == "coupon_claim":
    #     gap = feats.get("min_gap_seconds")
    #     if gap is not None and gap <= ??? and feats["event_count"] >= ???:
    #         _hit(hits, "R002", "领券间隔 %ds,累计 %d 次" % (gap, feats["event_count"]), "review")

    # ------------------------------------------------------------------
    # R003 金额异常
    #
    # 样本线索:
    #   u_1009 order amount=4999 → 盗号销赃场景
    #   u_1003~u_1005 order amount=9.9 → 灰产小额套现,金额不大但模式可疑
    #
    # 你要决定:
    #   - 只看 amount 绝对值,还是结合名单/设备灰度?
    #   - 阈值设多少?(4999 明显,9.9 需要和其他信号组合)
    #   - 未带 amount 的非 order 事件要不要跳过?
    # ------------------------------------------------------------------
    # TODO: 实现 R003
    #
    # 提示写法(按需删改):
    # if event_type == "order" and amount is not None and amount >= ???:
    #     _hit(hits, "R003", "订单金额 %.2f 超阈值" % amount, "review")

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
