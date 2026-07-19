# -*- coding: utf-8 -*-
"""规则回测工具:对全量标注账号跑规则集,输出混淆矩阵与 precision/recall/F1。

设计约定:指标计算是确定性代码,不让模型心算 —— 模型只负责解读结果、
提出调参假设,再用 overrides 做 what-if 验证(临时生效、不落盘),
形成"改阈值 → 看指标"的闭环。

口径:标签标在账号上,账号任一事件被规则标记,即视为该账号被标记。
两个 operating point 一起报:
  flag=review+reject —— 宽口径,review 也算拦下(有人工兜底)
  flag=reject_only   —— 严口径,只算硬拦截
两者的差值就是"人工审核队列在扛多少召回",是评估 gray→review 这类
柔性处置价值的直接证据。
"""
from typing import Dict, Iterable, List, Optional

from . import tool
from . import rules
from .datasource import load_events, load_labels
from .rules import rule_eval

# 可被 what-if 覆盖的阈值:参数名 -> rules 模块里的常量名
OVERRIDABLE = {
    "r002_max_gap_seconds": "R002_MAX_GAP_SECONDS",
    "r002_min_events": "R002_MIN_EVENTS",
    "r002_reject_min_ips": "R002_REJECT_MIN_IPS",
    "r003_high_amount": "R003_HIGH_AMOUNT",
    "r003_cashout_max_amount": "R003_CASHOUT_MAX_AMOUNT",
    "r003_cashout_min_coupons": "R003_CASHOUT_MIN_COUPONS",
}


def account_verdicts(uids: Iterable[str], events: List[Dict]) -> Dict[str, Dict]:
    """逐账号跑规则集:账号内任一事件命中即记入,处置取最重。
    scan_all(全量巡检)与 backtest(指标回测)共用这一份口径。"""
    verdicts = {}
    for uid in uids:
        worst = "pass"
        hit_rules: set = set()
        reasons: List[str] = []
        for e in (e for e in events if e["uid"] == uid):
            r = rule_eval(e)
            if rules.ACTION_ORDER[r["action"]] > rules.ACTION_ORDER[worst]:
                worst = r["action"]
            for h in r["hits"]:
                if h["rule_id"] not in hit_rules:
                    reasons.append("%s: %s" % (h["rule_id"], h["reason"]))
                hit_rules.add(h["rule_id"])
        verdicts[uid] = {"predicted": worst, "rules": sorted(hit_rules), "reasons": reasons[:3]}
    return verdicts


def _prf(tp: int, fp: int, fn: int) -> Dict[str, float]:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f1, 4)}


def backtest(overrides: Optional[Dict] = None):
    """核心逻辑,同时供工具调用、chart_threshold_sweep 与离线 eval 复用。"""
    overrides = overrides or {}
    applied, saved = {}, {}
    for k, v in overrides.items():
        if k not in OVERRIDABLE:
            return {"error": "不支持的阈值参数: %s(可用: %s)" % (k, ", ".join(OVERRIDABLE))}
        const = OVERRIDABLE[k]
        saved[const] = getattr(rules, const)
        setattr(rules, const, v)  # rule_eval 读的是 rules 模块全局,这里改了立即生效
        applied[k] = v
    try:
        labels = load_labels()
        events = load_events()
        verdicts = account_verdicts(labels.keys(), events)
        per_account = {
            uid: {"label": labels[uid]["label"], "predicted": v["predicted"], "rules": v["rules"]}
            for uid, v in verdicts.items()
        }

        points = {}
        for point, flagged_actions in (("flag=review+reject", ("review", "reject")),
                                       ("flag=reject_only", ("reject",))):
            tp = fp = fn = tn = 0
            for a in per_account.values():
                flagged = a["predicted"] in flagged_actions
                fraud = a["label"] == "fraud"
                if flagged and fraud:
                    tp += 1
                elif flagged:
                    fp += 1
                elif fraud:
                    fn += 1
                else:
                    tn += 1
            points[point] = {"tp": tp, "fp": fp, "fn": fn, "tn": tn, **_prf(tp, fp, fn)}

        misclassified = [
            {"uid": uid, "label": a["label"], "predicted": a["predicted"], "rules": a["rules"]}
            for uid, a in per_account.items()
            if (a["label"] == "fraud") != (a["predicted"] != "pass")
        ]
        return {
            "accounts_evaluated": len(per_account),
            "overrides_applied": applied,
            "operating_points": points,
            "per_account": per_account,
            "misclassified_at_review_point": misclassified,
        }
    finally:
        for const, v in saved.items():
            setattr(rules, const, v)


@tool(
    name="rule_backtest",
    description=(
        "对全量标注账号回测当前规则集,返回两个口径(flag=review+reject / flag=reject_only)"
        "的混淆矩阵与 precision/recall/F1、逐账号预测、误判清单。"
        "overrides 可临时覆盖阈值做 what-if(不修改配置),如 {\"r002_max_gap_seconds\": 60}。"
        "凡涉及规则效果/指标的问题必须用本工具取数,不要自行推算。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "overrides": {
                "type": "object",
                "description": "临时阈值覆盖,可用键:" + ", ".join(OVERRIDABLE),
            },
        },
    },
)
def rule_backtest(overrides: Optional[Dict] = None):
    return backtest(overrides)
