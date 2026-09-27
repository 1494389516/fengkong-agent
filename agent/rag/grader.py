"""Conservative retrieval grader for corrective RAG.

This is deliberately not an LLM judge. It checks whether retrieved material has
an auditable lexical bridge to the query and whether counterevidence searches
actually return caveat/boundary material. A PASS means "usable retrieval
context", not semantic entailment and not fraud confirmation.
"""
from .store import embedding_text, tokens

_STOP = frozenset(("的","了","是","在","与","和","或","及","为","有","也","不","不能",
                   "需要","可能","什么","是否","能否","怎么","如何","this","that","the","a",
                   "an","is","are","and","or","not","what","how","can"))
_COUNTER_TERMS = ("误报","边界","限制","合法","不能","可能","caveat","false positive",
                  "limitation","benign","boundary")


def _terms(text):
    return {t for t in tokens(text or "") if len(t) > 1 and t not in _STOP}


def grade_retrieval(query, hits, *, purpose="interpretation"):
    """Return an explainable retrieval sufficiency grade.

    The grader never manufactures evidence and never interprets retrieval
    relevance as risk probability.
    """
    if not hits:
        return {
            "status": "rewrite_required",
            "score": 0.0,
            "query_term_coverage": 0.0,
            "counterevidence_signal": False,
            "reason": "no_match",
            "semantic_relevance_verified": False,
        }

    query_terms = _terms(query)
    top = hits[:5]
    evidence_terms = set()
    for hit in top:
        evidence_terms |= _terms(embedding_text(hit))
    overlap = query_terms & evidence_terms
    coverage = len(overlap) / max(1, len(query_terms))

    counter_signal = any(
        any(term.casefold() in ("\n".join(str(hit.get(k, "")) for k in
            ("section", "text", "caveats", "applicability"))).casefold()
            for term in _COUNTER_TERMS)
        for hit in top
    )

    if not query_terms:
        status, reason = "rewrite_required", "query_has_no_gradeable_terms"
    elif coverage == 0:
        status, reason = "rewrite_required", "no_lexical_bridge"
    elif purpose == "counterevidence" and not counter_signal:
        status, reason = "rewrite_required", "counterevidence_not_found"
    else:
        status, reason = "pass", "auditable_lexical_bridge"

    return {
        "status": status,
        "score": round(coverage, 4),
        "query_term_coverage": round(coverage, 4),
        "counterevidence_signal": counter_signal,
        "reason": reason,
        "semantic_relevance_verified": False,
    }
