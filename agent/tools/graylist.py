# -*- coding: utf-8 -*-
"""灰名单生命周期工具:灰是观察态,必须走向结论,不能烂在名单里。

灰名单的三条出路(每条 gray 记录按观察期内的证据裁决):
  promote_to_black  实锤:关联账号出现 reject 判定 / 属实举报 / 聚集性
                    (>= graylist_promote_min_review 个关联账号命中 review)
  release           期满且干净:观察满 graylist_observe_days 天,关联账号
                    零命中 —— 继续挂着只会累积误伤,建议出灰
  observe           证据不足且观察未满:继续挂着,返回剩余天数

证据全部按当前策略口径重算(account_verdicts),时间基准用数据集时钟
(最新事件 ts)—— 离线数据没有"现在"。工具只出建议与提案素材,升黑走
blacklist_add、出灰走 blacklist_remove,生效都要人工 /approve。
"""
from datetime import datetime, timezone
from typing import Dict

from . import tool
from .backtest import account_verdicts
from .blacklist import _expired
from .datasource import load_blacklist, load_events, load_reports
from .policy import active_policy


def _date_ts(s: str) -> float:
    try:
        return datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=timezone.utc).timestamp()
    except (ValueError, TypeError):
        return 0.0


@tool(
    name="graylist_review",
    description=(
        "灰名单生命周期巡检:逐条评估 gray 记录的观察期证据(关联账号的当前"
        "判定、属实举报、聚集性),给出 promote_to_black(升黑)/ release(期满"
        "干净,出灰)/ observe(继续观察)建议与依据。升黑用 blacklist_add、"
        "出灰用 blacklist_remove 提交,均需 /approve。灰名单巡检应定期跑 —— "
        "永久挂灰既不定罪也不还清白,是名单治理的坏味道。"
    ),
    parameters={"type": "object", "properties": {}},
)
def graylist_review():
    p = active_policy()
    events = load_events()
    clock = max((e["ts"] for e in events), default=0)
    by_val: Dict[tuple, set] = {}
    for e in events:
        by_val.setdefault(("ip", e["ip"]), set()).add(e["uid"])
        by_val.setdefault(("device_id", e["device_id"]), set()).add(e["uid"])
    reports = load_reports()

    entries = []
    counts = {"promote_to_black": 0, "release": 0, "observe": 0}
    for rec in load_blacklist():
        if rec["list"] != "gray":
            continue
        dim, val = rec["dimension"], rec["value"]
        uids = [val] if dim == "uid" else sorted(by_val.get((dim, val), set()))
        verdicts = account_verdicts(uids, events) if uids else {}

        # 剔除自指证据:挂灰本身会让关联账号命中 R001-review,拿这个当"观察期
        # 证据"是自我实现的预言(挂灰 -> 全员 review -> 聚集性实锤 -> 升黑,
        # 且永远无法出灰)。只认 R001 之外的独立证据 —— 行为规则命中,或黑名单
        # 级 reject。代价:关联账号恰好命中另一条名单记录时会被当干净,观察期
        # 结论偏保守,可接受。
        def _independent(u):
            v = verdicts.get(u, {})
            return (v.get("predicted") in ("review", "reject")
                    and bool(set(v.get("rules", [])) - {"R001"}))
        flagged = [u for u in uids if _independent(u)]
        rejected = [u for u in flagged if verdicts.get(u, {}).get("predicted") == "reject"]
        vreports = sum(1 for r in reports
                       if r.get("reported_uid") in set(uids) and r.get("status") == "verified")
        days = max(0.0, (clock - _date_ts(rec.get("added_at", ""))) / 86400)
        observe_days = p["graylist_observe_days"]

        if rejected or vreports or len(flagged) >= p["graylist_promote_min_review"]:
            verdict = "promote_to_black"
            note = "实锤:reject 账号 %d / 属实举报 %d / review 命中 %d(聚集阈值 %d)" % (
                len(rejected), vreports, len(flagged), p["graylist_promote_min_review"])
        elif _expired(rec, clock) or (days >= observe_days and not flagged):
            verdict = "release"
            note = "观察 %.0f 天无命中(期 %d 天)%s,建议出灰止损误伤" % (
                days, observe_days, ",且记录已过期" if _expired(rec, clock) else "")
        else:
            verdict = "observe"
            note = "证据不足,继续观察(已 %.0f 天 / 期 %d 天,命中 %d)" % (
                days, observe_days, len(flagged))
        counts[verdict] += 1
        entries.append({
            "dimension": dim, "value": val, "reason": rec["reason"],
            "added_at": rec.get("added_at"), "days_observed": round(days, 1),
            "linked_accounts": len(uids), "flagged_accounts": flagged[:5],
            "verified_reports": vreports,
            "recommendation": verdict, "note": note,
        })
    return {
        "gray_total": len(entries),
        "recommendations": counts,
        "entries": entries,
        "note": "升黑:blacklist_add(list=black);出灰:blacklist_remove。均需 /approve 生效",
    }
