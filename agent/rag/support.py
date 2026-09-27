"""Conservative claim-to-knowledge support screening.

This module does NOT claim semantic entailment. It catches citations with no
meaningful lexical bridge to their cited material and marks the rest for
semantic review. Event evidence remains governed separately.
"""
from .store import tokens

_STOP = frozenset(("的","了","是","在","与","和","或","及","为","有","也","不","不能",
                   "需要","可能","this","that","the","a","an","is","are","and","or","not"))


def _terms(text):
    return {t for t in tokens(text or "") if len(t) > 1 and t not in _STOP}


def screen_claim(statement, materials):
    claim_terms = _terms(statement)
    if not materials:
        return {"status": "no_knowledge_material", "overlap_terms": [],
                "coverage": 0.0, "semantic_entailment_verified": False}
    evidence_text = "\n".join(
        "\n".join(str(item.get(k, "")) for k in
                  ("title", "section", "text", "caveats", "applicability"))
        for item in materials
    )
    evidence_terms = _terms(evidence_text)
    overlap = sorted(claim_terms & evidence_terms)
    coverage = len(overlap) / max(1, len(claim_terms))
    # Lexical overlap is only a triage signal. Even high overlap can contradict.
    status = "no_lexical_bridge" if not overlap else "semantic_review_required"
    return {"status": status, "overlap_terms": overlap[:20],
            "coverage": round(coverage, 4), "semantic_entailment_verified": False}


def audit_report_support(report, support_material):
    if not isinstance(report, dict):
        return {"status": "invalid_report", "claims": [],
                "semantic_entailment_verified": False}
    rows = []
    missing_bridge = []
    for index, claim in enumerate(report.get("claims", [])):
        ids = []
        for citation in claim.get("knowledge_citations", []):
            if isinstance(citation, str) and citation.startswith("[K:") and citation.endswith("]"):
                ids.append(citation[3:-1])
        materials = [support_material[key] for key in ids if key in support_material]
        screened = screen_claim(claim.get("statement", ""), materials)
        screened.update(index=index, knowledge_ids=ids)
        rows.append(screened)
        if ids and screened["status"] == "no_lexical_bridge":
            missing_bridge.append(index)
    return {
        "status": "lexical_gap" if missing_bridge else "semantic_review_required" if rows else "not_applicable",
        "claims": rows,
        "no_lexical_bridge_claim_indexes": missing_bridge,
        "semantic_entailment_verified": False,
        "interpretation": "Lexical screening only; contradiction/entailment still requires an independent evaluator.",
    }
