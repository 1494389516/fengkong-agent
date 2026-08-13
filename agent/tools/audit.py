# -*- coding: utf-8 -*-
"""审计查询工具:audit.jsonl 的只读侧。

审计日志之前只有写没有读:名单增删、阈值变更、申诉决议的每次审批
(approve/deny)都 append 一行,但没有任何工具让 agent 回答"这条名单是谁、
什么时候、依据什么批的"这类审计问题。audit_query 补上读侧,与
policy_history(阈值版本表)共同覆盖审计类问题的完整取证。
"""
import json
from typing import Any, Dict, List, Optional

from . import tool
from .datasource import audit_log_path

KINDS = ("blacklist_add", "blacklist_remove", "threshold_change", "appeal_resolve")
DECISIONS = ("approve", "deny")


def _load_records() -> List[Dict]:
    """逐行读 audit.jsonl,空行与损坏行跳过 —— 审计文件个别行损坏
    不应掀翻查询(损坏本身是数据治理问题,由对账/人工发现)。"""
    p = audit_log_path()
    if not p.exists():
        return []
    records: List[Dict] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


def _matches(rec: Dict[str, Any], kind: Optional[str], decision: Optional[str],
             dimension: Optional[str], value: Optional[str]) -> bool:
    """逐条件过滤。dimension/value 只对名单类记录有意义(藏在 action 里),
    其余 kind(threshold_change/appeal_resolve)不带这两个字段自然不命中。"""
    if kind and rec.get("kind") != kind:
        return False
    if decision and rec.get("decision") != decision:
        return False
    action = rec.get("action") or {}
    if dimension and action.get("dimension") != dimension:
        return False
    if value and action.get("value") != value:
        return False
    return True


@tool(
    name="audit_query",
    description=(
        "查询审批审计日志:谁在什么时候批准/驳回了什么、依据是什么。"
        "覆盖名单写入/移除(blacklist_add/blacklist_remove)、阈值变更"
        "(threshold_change)、申诉决议(appeal_resolve)四类记录,按时间倒序。"
        "配合 policy_history 可完整回溯'当时为什么这么判、谁批的'类问题。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "kind": {"type": "string", "enum": list(KINDS),
                     "description": "可选:只看某一类审批"},
            "decision": {"type": "string", "enum": list(DECISIONS),
                         "description": "可选:只看批准(approve)或驳回(deny)"},
            "dimension": {"type": "string", "enum": ["uid", "ip", "device_id"],
                          "description": "可选:名单类记录按维度过滤"},
            "value": {"type": "string",
                      "description": "可选:名单类记录按具体值过滤"},
            "limit": {"type": "integer",
                      "description": "最多返回条数,默认 20,最大 100"},
        },
    },
)
def audit_query(kind: str = "", decision: str = "", dimension: str = "",
                value: str = "", limit: int = 20):
    limit = max(1, min(int(limit or 20), 100))
    records = [r for r in _load_records()
               if _matches(r, kind or None, decision or None,
                           dimension or None, value or None)]
    records.reverse()  # 文件 append-only,倒序即时间倒序(最新在前)
    return {
        "count": len(records),
        "returned": min(limit, len(records)),
        "records": records[:limit],
    }
