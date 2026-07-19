# -*- coding: utf-8 -*-
"""举报记录工具:用户侧信号的查询入口。

机器特征探测不到的欺诈(社工、交易欺诈、杀猪盘)主要靠举报进来;
但举报也会被滥用(恶意举报竞争对手/正常用户),所以 status 必须区分:
verified 属实 / pending 待核 / dismissed 不实 —— dismissed 的记录
不得作为处置依据,反而是"该账号曾被误举报"的澄清证据。
"""
from . import tool
from .datasource import load_reports


@tool(
    name="report_query",
    description=(
        "查询举报记录。direction=against(默认,查被举报)或 by(查该账号发起的"
        "举报)。返回类别/内容/时间/处理状态(verified 属实 / pending 待核 / "
        "dismissed 不实)。verified 举报是强证据;dismissed 不得作为处置依据;"
        "频繁发起不实举报的账号本身可疑。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "uid": {"type": "string", "description": "用户 ID"},
            "direction": {"type": "string", "enum": ["against", "by"],
                          "description": "against=被举报(默认),by=发起的举报"},
        },
        "required": ["uid"],
    },
)
def report_query(uid: str, direction: str = "against"):
    key = "reported_uid" if direction == "against" else "reporter"
    hits = [r for r in load_reports() if r.get(key) == uid]
    return {
        "uid": uid,
        "direction": direction,
        "count": len(hits),
        "verified_count": sum(1 for r in hits if r.get("status") == "verified"),
        "reports": hits,
    }
