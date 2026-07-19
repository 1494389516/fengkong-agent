# -*- coding: utf-8 -*-
"""全量巡检工具:对当前数据集所有账号跑一遍规则集,按处置动作分组输出。

这是 agent 从"被动答题"到"主动值班"的入口:研究员一句"今天有哪些账号要
处理",一次调用拿到全量清单。口径与 rule_backtest 完全一致(共用
account_verdicts),巡检结论和回测指标不会打架。

token 约束:pass 的账号只给计数不给清单(绝大多数账号是正常的,列出来
纯属浪费);reject/review 清单经 dispatch ② 限幅,超长自动截断并带计数。
"""
from . import tool
from .backtest import account_verdicts
from .datasource import load_events


@tool(
    name="scan_all",
    description=(
        "全量巡检:对当前数据集的所有账号跑规则集,返回 reject/review 两组账号"
        "清单(含命中规则与理由)及 pass 计数。适合'今天有哪些账号要处理'"
        "'给我一份风险日报'类问题。清单过长会自动截断并注明总数。"
    ),
    parameters={"type": "object", "properties": {}},
)
def scan_all():
    events = load_events()
    uids = sorted({e["uid"] for e in events})
    verdicts = account_verdicts(uids, events)
    groups = {"reject": [], "review": []}
    pass_count = 0
    for uid, v in verdicts.items():
        if v["predicted"] == "pass":
            pass_count += 1
        else:
            groups[v["predicted"]].append(
                {"uid": uid, "rules": v["rules"], "reasons": v["reasons"]})
    return {
        "accounts_total": len(uids),
        "reject_count": len(groups["reject"]),
        "review_count": len(groups["review"]),
        "pass_count": pass_count,
        "reject": groups["reject"],
        "review": groups["review"],
    }
