from .storage import order_column
"""Bounded, structured memory for repeated risk investigations.

Memory is reconstructed from prior durable tasks in the same tenant/app/entity
scope. Raw LLM summaries and claim prose are intentionally excluded so previous
generated text cannot become instructions in a later investigation.
"""
import json
import math


def _finite_number(value):
    return value if type(value) in (int, float) and math.isfinite(value) else None


def load_investigation_memory(db, snapshot, limit=3):
    if type(limit) is not int or not 1 <= limit <= 10:
        raise ValueError("memory limit must be 1..10")
    required = ("tenant_id", "app_id", "entity_ref", "case_id", "as_of")
    if any(key not in snapshot for key in required):
        raise ValueError("snapshot lacks memory scope")

    rows = db.execute(
        "SELECT c.case_id,t.snapshot,t.result FROM cases c "
        "JOIN investigation_tasks t ON t.case_id=c.case_id "
        "WHERE c.tenant=? AND c.app=? AND c.entity=? AND c.case_id<>? "
        "AND t.status='success' ORDER BY c.bucket DESC, " + order_column(db,"c") + " DESC LIMIT ?",
        (snapshot["tenant_id"], snapshot["app_id"], snapshot["entity_ref"],
         snapshot["case_id"], limit * 4),
    ).fetchall()

    memory = []
    for case_id, old_snapshot_raw, result_raw in rows:
        try:
            old_snapshot = json.loads(old_snapshot_raw)
            result = json.loads(result_raw)
        except Exception:
            continue
        old_as_of = _finite_number(old_snapshot.get("as_of"))
        if old_as_of is None or old_as_of >= snapshot["as_of"]:
            continue  # PIT: never remember the future or same-time task.
        decision = old_snapshot.get("decision") if isinstance(old_snapshot.get("decision"), dict) else {}
        report = result.get("investigation_report") if isinstance(result.get("investigation_report"), dict) else {}
        claim_audit = result.get("claim_evidence_audit") if isinstance(result.get("claim_evidence_audit"), dict) else {}
        retrieval = result.get("retrieval_audit") if isinstance(result.get("retrieval_audit"), dict) else {}
        entry = {
            "as_of": old_as_of,
            "recommendation_eligibility":result.get('recommendation_eligibility','unverified'),
            "evidence_status":result.get('evidence_status','unverified'),
            "label_source":"model_suggestion",
            "human_confirmed":False,
            "decision_action": decision.get("action") if decision.get("action") in
                ("pass", "review", "reject", "deny", "challenge") else "unknown",
            "investigation_verdict": report.get("verdict") if report.get("verdict") in
                ("evidence_gap", "needs_review", "risk_supported", "benign_explanation_supported")
                else "unknown",
            "retrieval_outcome": retrieval.get("outcome", "unknown"),
            "claim_count": claim_audit.get("claim_count", 0)
                if type(claim_audit.get("claim_count", 0)) is int else 0,
            "unsupported_claim_count": len(claim_audit.get("unsupported_claim_indexes", []))
                if isinstance(claim_audit.get("unsupported_claim_indexes", []), list) else 0,
        }
        score = _finite_number(decision.get("risk_score"))
        if score is not None:
            entry["risk_score"] = score
        memory.append(entry)
        if len(memory) >= limit:
            break
    return {
        "entries": memory,
        "count": len(memory),
        "raw_text_included": False,
        "interpretation": "Prior structured outcomes only; not current evidence and not an execution signal.",
    }
