# -*- coding: utf-8 -*-
"""label_conflicts 代理:复用 label_quality 的冲突口径,供 feedback_pipeline
与 readiness 聚合(避免直接依赖 eval/ 目录)。"""
from typing import List


def label_conflicts() -> List[dict]:
    from .backtest import account_verdicts
    from .datasource import load_events, load_labels
    labels = load_labels()
    events = load_events()
    if not labels:
        return []
    verdicts = account_verdicts(labels.keys(), events)
    out = []
    for u, v in verdicts.items():
        pred = v.get("predicted", "pass")
        lab = labels[u]["label"]
        if lab == "normal" and pred != "pass":
            out.append({"uid": u, "type": "label_normal_but_flagged",
                        "predicted": pred})
        elif lab == "fraud" and pred == "pass":
            out.append({"uid": u, "type": "label_fraud_but_passed",
                        "predicted": pred})
    return out
