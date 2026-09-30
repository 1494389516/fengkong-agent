"""RAG evaluation scorecard for risk investigations.

Inspired by claim-level RAG evaluation practice, but intentionally dependency-free.
It separates retrieval quality, grounding/workflow quality and leakage/security
probes. Synthetic fixtures validate the evaluator contract; real investigation
JSONL can be supplied with --investigations for actual Agent-output metrics.

Usage:
  python -m eval.rag_scorecard
  python -m eval.rag_scorecard --investigations out/investigations.jsonl
"""
import argparse
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from agent.rag.store import ingest, search, tokens


def _load_jsonl(path):
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines()
            if line.strip()]


def _mean(values):
    return sum(values) / len(values) if values else None


def _term_set(text):
    return {term for term in tokens(text or "") if len(term) > 1}


def retrieval_metrics(corpus="knowledge"):
    basic = _load_jsonl("eval/rag/cases.jsonl")
    hard = _load_jsonl("eval/rag/hard_cases.jsonl")
    context_cases = _load_jsonl("eval/rag/context_cases.jsonl")
    rows = []
    context_recalls = []
    with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"FK_DATA_DIR": directory}):
        ingest(corpus)
        for suite, cases in (("basic", basic), ("hard", hard)):
            for case in cases:
                result = search(case["query"], platform=case["platform"], top_k=5)
                ids = [hit["knowledge_id"] for hit in result["hits"]]
                expected = case["expected_knowledge_id"]
                rank = next((i + 1 for i, value in enumerate(ids) if value == expected), None) if expected else None
                section_ok = None
                if expected and case.get("expected_section"):
                    section_ok = bool(result["hits"] and
                                      result["hits"][0]["knowledge_id"] == expected and
                                      result["hits"][0]["section"] == case["expected_section"])
                rows.append({
                    "suite": suite, "query": case["query"], "expected": expected,
                    "rank": rank, "negative_empty": (not ids) if expected is None else None,
                    "section_top1": section_ok,
                })

        for case in context_cases:
            result = search(case["query"], platform=case["platform"], top_k=5)
            actual = {(hit["knowledge_id"], hit["section"]) for hit in result["hits"]}
            expected = {tuple(item) for item in case["expected_chunks"]}
            context_recalls.append(len(actual & expected) / len(expected) if expected else 1.0)

        # PIT leakage probe: checked-in knowledge is newer than this historical anchor.
        pit = search("DebuggerDetector", platform="ios",
                     as_of="2026-01-01T00:00:00+00:00", top_k=5)
        # Cross-platform isolation is a second deterministic leakage boundary.
        platform = search("DebuggerDetector", platform="android", top_k=5)

    positives = [r for r in rows if r["expected"]]
    negatives = [r for r in rows if r["expected"] is None]
    hard_positive = [r for r in rows if r["suite"] == "hard" and r["expected"]]
    return {
        "fixture_kind": "synthetic retrieval benchmark; not incident validation",
        "query_count": len(rows),
        "positive_count": len(positives),
        "negative_count": len(negatives),
        "hit_at_1": _mean([r["rank"] == 1 for r in positives]),
        "hit_at_5": _mean([r["rank"] is not None and r["rank"] <= 5 for r in positives]),
        "mrr_at_5": _mean([1.0 / r["rank"] if r["rank"] and r["rank"] <= 5 else 0.0 for r in positives]),
        "negative_rejection_rate": _mean([r["negative_empty"] for r in negatives]),
        "hard_section_top1": _mean([r["section_top1"] for r in hard_positive
                                     if r["section_top1"] is not None]),
        "context_recall_at_5": _mean(context_recalls),
        "context_recall_case_count": len(context_recalls),
        "pit_future_knowledge_blocked": not pit["hits"],
        "cross_platform_leakage_blocked": not platform["hits"],
    }


def investigation_metrics(records):
    """Aggregate already-produced investigation results without re-judging text."""
    if not records:
        return {
            "record_count": 0,
            "note": "No real investigation outputs supplied; generator metrics are not claimed.",
        }
    report_valid = []
    citation_valid = []
    structural_grounding = []
    counter_complete = []
    lexical_bridge = []
    semantic_verified = []
    unsupported_rates = []
    gold_context_recall = []
    answer_relevance_proxy = []
    for row in records:
        report = row.get("investigation_report")
        claim_audit = row.get("claim_evidence_audit") or {}
        citation = row.get("knowledge_citation_audit") or {}
        retrieval = row.get("retrieval_audit") or {}
        support = row.get("claim_support_audit") or {}
        entailment = row.get("claim_entailment_audit") or {}
        report_valid.append(isinstance(report, dict))
        citation_valid.append({
            "references_present": True, "invalid_references": False,
        }.get(citation.get("status")))
        claims = claim_audit.get("claims")
        complete_grounding = (isinstance(claims, list) and bool(claims)
                              and all(isinstance(c, dict)
                                      and type(c.get("structurally_supported")) is bool
                                      for c in claims))
        structural_grounding.append(
            _mean([c["structurally_supported"] for c in claims])
            if complete_grounding else None)
        counter_outcome = retrieval.get("outcome")
        counter_status = {
            "balanced": True,
            "counterevidence_not_checked": False,
            "counterevidence_incomplete": False,
            "retrieval_incomplete": False,
        }.get(counter_outcome)
        if counter_outcome in ("knowledge_gap", "exhausted_no_match"):
            performed = retrieval.get("counterevidence_search_performed")
            counter_status = performed if type(performed) is bool else None
        counter_complete.append(counter_status)
        support_claims = support.get("claims")
        bridge_checks = []
        complete_bridge = isinstance(support_claims, list)
        for claim in support_claims if complete_bridge else []:
            if (not isinstance(claim, dict)
                    or not isinstance(claim.get("knowledge_ids"), list)
                    or any(not isinstance(ident, str) or not ident
                           for ident in claim["knowledge_ids"])):
                complete_bridge = False
                break
            if not claim["knowledge_ids"]:
                continue
            checked = {
                "no_lexical_bridge": False, "semantic_review_required": True,
            }.get(claim.get("status"))
            if checked is None:
                complete_bridge = False
                break
            bridge_checks.append(checked)
        lexical_bridge.append(_mean(bridge_checks) if complete_bridge else None)
        verified = entailment.get("semantic_entailment_verified")
        semantic_verified.append(verified if type(verified) is bool else None)
        count = claim_audit.get("claim_count")
        unsupported = claim_audit.get("unsupported_claim_indexes")
        unsupported_rates.append(
            len(unsupported) / count
            if (type(count) is int and count > 0 and isinstance(unsupported, list)
                and all(type(index) is int and 0 <= index < count for index in unsupported)
                and len(set(unsupported)) == len(unsupported)
                and claim_audit.get("status") in
                ("structurally_grounded", "unsupported_claims", "workflow_incomplete"))
            else None)

        gold = row.get("gold_evidence_refs")
        if isinstance(gold, list) and gold:
            expected = {str(value).removeprefix("[K:").removesuffix("]") for value in gold}
            retrieved_ids = {
                hit_id
                for attempt in retrieval.get("attempts", [])
                for hit_id in attempt.get("hit_ids", [])
                if isinstance(hit_id, str)
            }
            gold_context_recall.append(len(expected & retrieved_ids) / len(expected))

        evaluation_query = row.get("evaluation_query")
        if isinstance(evaluation_query, str) and evaluation_query.strip() and isinstance(report, dict):
            answer = " ".join(
                claim.get("statement", "") for claim in report.get("claims", [])
                if isinstance(claim, dict)
            )
            q_terms = _term_set(evaluation_query)
            a_terms = _term_set(answer)
            answer_relevance_proxy.append(len(q_terms & a_terms) / max(1, len(q_terms)))

    def present(values):
        return [v for v in values if v is not None]

    return {
        "record_count": len(records),
        "report_parse_rate": _mean(report_valid),
        "citation_reference_validity_rate": _mean(present(citation_valid)),
        "citation_reference_validity_record_count": len(present(citation_valid)),
        "structurally_grounded_claim_rate": _mean(present(structural_grounding)),
        "structurally_grounded_record_count": len(present(structural_grounding)),
        "counterevidence_workflow_complete_rate": _mean(present(counter_complete)),
        "counterevidence_workflow_record_count": len(present(counter_complete)),
        "knowledge_lexical_bridge_rate": _mean(present(lexical_bridge)),
        "knowledge_lexical_bridge_record_count": len(present(lexical_bridge)),
        "unsupported_claim_rate": _mean(present(unsupported_rates)),
        "unsupported_claim_record_count": len(present(unsupported_rates)),
        "gold_context_recall": _mean(gold_context_recall),
        "gold_context_recall_record_count": len(gold_context_recall),
        "answer_relevance_lexical_proxy": _mean(answer_relevance_proxy),
        "answer_relevance_record_count": len(answer_relevance_proxy),
        "answer_relevance_note": (
            "Lexical query-to-claim coverage only; this is not a semantic relevance judge."
        ),
        "semantic_entailment_verified_rate": _mean(present(semantic_verified)),
        "semantic_entailment_record_count": len(present(semantic_verified)),
        "semantic_entailment_note": (
            "Read from claim_entailment_audit, not the lexical support screen; "
            "verification requires an independently calibrated evaluator."
        ),
        "audit_coverage_note": (
            "Missing, partial, malformed or unrecognized audit results are unknown and excluded from rates; "
            "record counts show each denominator. No citations and unused retrieval are "
            "not applicable, not successful checks."
        ),
        "claim_rate_aggregation_note": (
            "Structural grounding, lexical bridge and unsupported-claim rates are macro "
            "averages of per-record claim fractions. Each audited record has equal weight; "
            "these are not pooled claim-level rates."
        ),
    }


def contract_fixture_metrics():
    """Check that bad grounding is detected; this is evaluator QA, not Agent quality."""
    from agent.rag.reporting import claim_evidence_audit, citation_audit
    from agent.rag.support import audit_report_support

    retrieved = {"k1": {
        "chunk_id": "k1", "source": "fixture", "section": "误报与能力边界",
        "content_hash": "fixture", "known_at": "2026-01-01T00:00:00+00:00",
        "reviewed_at": "2026-01-01T00:00:00+00:00", "applicability": "fixture",
        "retrieval_purposes": ["counterevidence"],
    }}
    material = {"k1": {
        "title": "调试器与断点检测", "section": "误报与能力边界",
        "text": "合法开发调试也可能命中。", "caveats": "不能单独证明欺诈。",
        "applicability": "synthetic evaluator fixture",
    }}
    event_registry = {"event:e1": {"kind": "event_fact"}}
    retrieval = {"outcome": "balanced", "failed_count": 0}

    good = {
        "verdict": "needs_review",
        "claims": [
            {"statement": "事件存在已记录事实，需要结合其他证据判断。",
             "role": "finding", "event_evidence": ["event:e1"],
             "knowledge_citations": [], "confidence": "medium"},
            {"statement": "合法开发调试也可能命中，不能单独证明欺诈。",
             "role": "counterevidence", "event_evidence": [],
             "knowledge_citations": ["[K:k1]"], "confidence": "medium"},
        ],
        "missing_evidence": ["独立行为证据"],
        "recommended_next_step": "人工复核",
    }
    good_text = json.dumps(good, ensure_ascii=False)
    _, good_claim = claim_evidence_audit(good_text, retrieved, event_registry, retrieval)
    good_support = audit_report_support(good, material)
    good_citation = citation_audit(good_text, retrieved)

    bad_unknown = dict(good)
    bad_unknown["claims"] = [
        {"statement": "未知引用不应通过。",
         "role": "finding", "event_evidence": ["event:missing"],
         "knowledge_citations": ["[K:missing]"], "confidence": "high"}
    ]
    bad_unknown_text = json.dumps(bad_unknown, ensure_ascii=False)
    _, bad_claim = claim_evidence_audit(
        bad_unknown_text, retrieved, event_registry, retrieval)
    bad_citation = citation_audit(bad_unknown_text, retrieved)

    bad_unrelated = dict(good)
    bad_unrelated["claims"] = [
        {"statement": "该账号已经完成跨境洗钱并确认团伙身份。",
         "role": "counterevidence", "event_evidence": [],
         "knowledge_citations": ["[K:k1]"], "confidence": "high"}
    ]
    bad_support = audit_report_support(bad_unrelated, material)

    checks = {
        "valid_fixture_accepted": (
            good_claim["status"] in ("structurally_grounded", "workflow_incomplete")
            and good_citation["status"] == "references_present"
            and not good_support["no_lexical_bridge_claim_indexes"]
        ),
        "unknown_evidence_detected": bad_claim["status"] == "unsupported_claims",
        "unknown_citation_detected": bad_citation["status"] == "invalid_references",
        "lexical_gap_detected": bad_support["status"] == "lexical_gap",
    }
    return {"fixture_kind": "synthetic evaluator-contract QA", **checks,
            "contract_accuracy": _mean(list(checks.values()))}


def evaluate(investigations=None):
    retrieval = retrieval_metrics()
    contract = contract_fixture_metrics()
    generator = investigation_metrics(investigations or [])
    return {
        "schema_version": 2,
        "interpretation": (
            "Retriever metrics use synthetic checked-in queries. Generator metrics are reported only "
            "when real investigation outputs are explicitly supplied. No metric here is fraud-model quality."
        ),
        "retriever": retrieval,
        "grounding_evaluator_contract": contract,
        "generator_grounding": generator,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--investigations", help="JSONL of completed investigation result objects")
    parser.add_argument("--output", help="optional scorecard JSON path")
    parser.add_argument("--gate", action="store_true",
                        help="fail on checked-in retrieval/evaluator contract regression")
    args = parser.parse_args()
    records = _load_jsonl(args.investigations) if args.investigations else []
    scorecard = evaluate(records)
    text = json.dumps(scorecard, ensure_ascii=False, indent=2)
    print(text)
    if args.output:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8")
    if args.gate:
        r = scorecard["retriever"]
        c = scorecard["grounding_evaluator_contract"]
        required = (
            r["hit_at_5"] == 1.0
            and r["negative_rejection_rate"] == 1.0
            and r["hard_section_top1"] == 1.0
            and r["pit_future_knowledge_blocked"]
            and r["cross_platform_leakage_blocked"]
            and c["contract_accuracy"] == 1.0
        )
        return 0 if required else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
