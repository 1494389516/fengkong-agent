# -*- coding: utf-8 -*-
"""值班日报工具:一次调用拿全风险面,"主动值班"的收口。

没有它之前,研究员早上要问五个问题才能拿全风险面:规则命中了谁(scan)、
特征漂没漂(feature_drift)、规则输出稳不稳(rule_drift)、对手在不在适应
(adversary_watch)、特征还灵不灵(feature_risk 衰减)、有没有人喊冤
(appeal_review)。日报把它们聚合成一份,且只带"有事的项" —— 各监控的
alert_text 本来就为此设计(无告警为 None,不占日报一行)。

口径约定:日报只做汇总与转述,不重算任何指标 —— 每个数字都可以用对应
单项工具复现(深挖入口在 note 里)。安静的项列在 quiet 里,让"今天没事"
也是一个明确结论,而不是"没查"。
"""
from typing import Dict, List

from . import tool
from .adversary import adversary_watch
from .datasource import load_appeals, postmortems_path
from .drift import feature_drift, rule_drift
from .risk import feature_risk
from .scan import scan_all


@tool(
    name="daily_brief",
    description=(
        "值班日报:一次聚合全风险面 —— 规则命中清单、特征/规则输出漂移、对抗面"
        "(阈值试探/团伙扩张)、区分度衰减、待处理申诉;有告警的进 alerts,安静的"
        "进 quiet。'今天有哪些要处理''风险日报'类问题用它,深挖再调单项工具。"
    ),
    parameters={"type": "object", "properties": {}},
)
def daily_brief():
    alerts: Dict[str, object] = {}
    quiet: List[str] = []

    # 告警按确认状态分流(ops.filter_acked):已确认的只计数,恶化的重浮
    from .ops import filter_acked, watched_status

    def _collect(name: str, report: Dict, raw_alarms: List[str] = None):
        raw = raw_alarms if raw_alarms is not None else (report.get("alarms") or [])
        if report.get("found") is False:
            quiet.append("%s(数据不足以分桶)" % name)
            return
        flt = filter_acked(raw)
        if report.get("tail_bucket_partial") and flt["active"]:
            flt["active"].append("(末桶可能未采集完整,告警需复核)")
        if flt["active"]:
            alerts[name] = flt["active"]
        else:
            quiet.append(name + ("(已确认 %d 条)" % flt["acked_count"]
                                 if flt["acked_count"] else ""))
        acked_total[0] += flt["acked_count"]

    acked_total = [0]
    sc = scan_all()
    rd = rule_drift()
    _collect("feature_drift", feature_drift())
    _collect("rule_drift", rd)
    _collect("adversary_watch", adversary_watch())
    fr = feature_risk(time_grain="day")
    decay = (fr.get("risk_trend") or {}).get("decay_alarms") or []
    _collect("feature_decay", {"found": True}, decay)

    appeals_pending = sum(1 for a in load_appeals() if a.get("status") == "pending")
    pm = postmortems_path()
    postmortems = sum(1 for _ in pm.open(encoding="utf-8")) if pm.exists() else 0

    out = {
        "verdicts": {
            "reject": [x["uid"] for x in sc["reject"]],
            "review": [x["uid"] for x in sc["review"]],
            "pass_count": sc["pass_count"],
        },
        "alerts": alerts,
        "alert_count": len(alerts),
        "acked_alarms": acked_total[0],
        "quiet": quiet,
        **({"watched": ws} if (ws := watched_status()) else {}),
        "appeals_pending": appeals_pending,
        "postmortems_total": postmortems,
        "note": "深挖:命中理由 scan_all;漂移 feature_drift/rule_drift;对抗 "
                "adversary_watch;衰减 feature_risk(time_grain);申诉 appeal_review;"
                "告警确认/盯梢 duty_ops",
    }
    # 模拟失信标记跟着聚合走:rule_drift 是模拟类,它带了就必须转述
    sim = rd.get("sim_consistency")
    if sim is not None:
        out["sim_consistency"] = sim
    return out
