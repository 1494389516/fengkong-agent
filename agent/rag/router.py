"""Advisory router across risk evidence planes.

Routing is deterministic and side-effect free. It narrows which read-only plane
should answer a question; it never grants capabilities and never executes a
decision.
"""
from agent.rag.store import tokens

_PLANES = ("event_store", "knowledge_rag", "risk_graph", "rule_engine")

_CUES = {
    "event_store": ("最近","历史","事件","登录","订单","时间","变化","event","recent","history","timeline"),
    "knowledge_rag": ("为什么","原理","解释","检测","误报","文档","源码","detector","why","explain","caveat","documentation"),
    "risk_graph": ("关联","团伙","共享","关系","设备","ip","图","cluster","relation","shared","graph","community"),
    "rule_engine": ("规则","策略","封禁","拒绝","决策","阈值","命中","rule","policy","decision","threshold","block","reject"),
}


def route_query(query):
    if not isinstance(query, str) or not query.strip() or len(query) > 2000:
        raise ValueError("query must contain 1..2000 characters")
    normalized = query.casefold()
    token_set = set(tokens(query))
    scored = []
    for plane in _PLANES:
        cues = _CUES[plane]
        matched = sorted({
            cue for cue in cues
            if cue.casefold() in normalized or cue.casefold() in token_set
        })
        if matched:
            scored.append((plane, len(matched), matched[:8]))

    if not scored:
        # Unknown risk questions start from immutable facts, not RAG.
        return {
            "primary": "event_store",
            "planes": [{"plane": "event_store", "reason": "default_fact_first"}],
            "execute_allowed": False,
            "interpretation": "Advisory read routing only; capabilities remain server-owned.",
        }

    scored.sort(key=lambda item: (-item[1], _PLANES.index(item[0])))
    return {
        "primary": scored[0][0],
        "planes": [
            {"plane": plane, "reason": "query_cues", "matched_cues": matched}
            for plane, _, matched in scored
        ],
        "execute_allowed": False,
        "interpretation": "Advisory read routing only; capabilities remain server-owned.",
    }
