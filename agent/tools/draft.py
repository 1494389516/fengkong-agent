# -*- coding: utf-8 -*-
"""候选规则试衣间:声明式规则草案在历史数据上试跑,不存储、不生效。

这是策略生命周期里"起草 → 验证"的一步:agent 发现新模式(如 feature_risk
显示某特征 IV 高、adversary_watch 报阈值试探)后,可以把假设写成声明式
条件立刻试穿 —— 会命中谁、精确率多少、和现有规则重叠多少、能不能抓到
现在漏掉的欺诈(net_new_catches,这是加规则的唯一正当理由)。

边界(为什么只是试衣间):
- 无存储无生效:草案不进任何配置,试完即弃。把草案变成正式规则仍是
  研究员写代码 + 评审 + eval 的事 —— 规则是生产逻辑,不走数据配置后门。
- 账号级口径:条件作用在账号全历史特征上(window_seconds 可选窗口),
  与逐事件 point-in-time 回测是两个口径 —— 试衣间答"这个方向值不值得
  做",精确指标等正式实现后由 rule_backtest 出。数字会有偏差,方向不会。
"""
from typing import Dict, List, Optional

from . import tool
from .backtest import account_verdicts
from .datasource import load_events, load_labels
from .featurelib import account_features

# 草案条件可用的特征(account_features 的数值字段)与算子
DRAFT_FEATURES = ("event_count", "distinct_ip", "distinct_device", "coupon_claims",
                  "order_count", "order_amount_max", "order_amount_sum",
                  "min_gap_seconds", "span_seconds")
OPS = {">=": lambda a, b: a >= b, "<=": lambda a, b: a <= b,
       ">": lambda a, b: a > b, "<": lambda a, b: a < b, "==": lambda a, b: a == b}


@tool(
    name="rule_draft_test",
    description=(
        "候选规则试跑(不存储不生效):conditions 为特征条件列表(全满足才命中,"
        "特征见参数说明,算子 >=/<=/>/</==)。返回命中账号、精确率、与现有规则的"
        "重叠及 net_new_catches(现有规则漏掉而草案能抓的欺诈 —— 加规则的唯一"
        "正当理由)。方向验证用;转正式规则需研究员写码评审。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "conditions": {
                "type": "array",
                "description": "条件列表(特征可用 " + "/".join(DRAFT_FEATURES) + ")",
                "items": {
                    "type": "object",
                    "properties": {
                        "feature": {"type": "string"},
                        "op": {"type": "string", "enum": list(OPS)},
                        "value": {"type": "number"},
                    },
                    "required": ["feature", "op", "value"],
                },
            },
            "window_seconds": {"type": "integer",
                               "description": "可选:特征只看每账号最近 N 秒(锚定其末事件)"},
        },
        "required": ["conditions"],
    },
)
def rule_draft_test(conditions: List[Dict], window_seconds: Optional[int] = None):
    if not conditions:
        return {"error": "conditions 不能为空"}
    for c in conditions:
        if c.get("feature") not in DRAFT_FEATURES:
            return {"error": "未知特征: %s,可选: %s" % (c.get("feature"), list(DRAFT_FEATURES))}
        if c.get("op") not in OPS:
            return {"error": "未知算子: %s,可选: %s" % (c.get("op"), list(OPS))}

    uids = sorted({e["uid"] for e in load_events()})
    hit_uids = []
    for uid in uids:
        f = account_features(uid, None, window_seconds)
        if not f.get("found"):
            continue
        ok = True
        for c in conditions:
            v = f.get(c["feature"])
            if v is None or not OPS[c["op"]](v, c["value"]):
                ok = False
                break
        if ok:
            hit_uids.append(uid)

    labels = {u: v["label"] for u, v in load_labels().items()}
    labeled_hits = [u for u in hit_uids if u in labels]
    tp = [u for u in labeled_hits if labels[u] == "fraud"]
    fp = [u for u in labeled_hits if labels[u] == "normal"]

    # 与现有规则集的关系:重叠部分是冗余,net_new 才是增量价值。
    # 覆盖判定必须对全部命中账号跑规则(account_verdicts),不能借用 backtest
    # 的 per_account —— 那只覆盖有标签账号,无标签命中会被当成"已覆盖",
    # 恰恰漏掉草案最有价值的场景:现有规则和标签都没碰过的新模式。
    verdicts = account_verdicts(hit_uids, load_events()) if hit_uids else {}
    flagged = {u for u, a in verdicts.items() if a["predicted"] != "pass"}
    already_flagged = [u for u in hit_uids if u in flagged]
    net_new = [u for u in tp if u not in flagged]           # 现在漏掉、草案能抓
    net_new_fp = [u for u in fp if u not in flagged]        # 草案新引入的误伤
    # 无标签且现有规则未覆盖:定性未知的真增量候选,交人工核查
    net_new_unlabeled = [u for u in hit_uids if u not in labels and u not in flagged]

    precision = round(len(tp) / len(labeled_hits), 4) if labeled_hits else None
    return {
        "conditions": conditions,
        "window_seconds": window_seconds,
        "hit_count": len(hit_uids),
        "hit_accounts": hit_uids,
        "labeled_hits": len(labeled_hits),
        "precision_on_labeled": precision,
        "tp": len(tp), "fp": len(fp),
        "overlap_with_active_rules": len(already_flagged),
        "net_new_catches": net_new,
        "net_new_false_positives": net_new_fp,
        "net_new_unlabeled": net_new_unlabeled,
        "verdict": (
            "无命中,条件过严或方向不对" if not hit_uids else
            "全部命中已被现有规则覆盖,草案无增量"
            if not (net_new or net_new_fp or net_new_unlabeled) else
            "有增量召回且无新误伤,值得转正式实现" if net_new and not net_new_fp else
            "有增量但引入新误伤,收紧条件或叠加信号" if net_new else
            "无增量召回还引入新误伤,放弃此方向" if net_new_fp else
            "增量命中均无标签,先人工核查这些账号再定方向"),
        "note": "账号级口径的方向验证;转正式规则需研究员实现 + 评审 + eval 回归",
    }
