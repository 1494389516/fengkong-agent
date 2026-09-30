"""Scorecard audit aggregation regressions; no model or network dependency."""
import unittest

from eval.rag_scorecard import investigation_metrics


class RAGScorecardRegression(unittest.TestCase):
    def test_missing_audits_are_unknown_not_successful(self):
        result = investigation_metrics([{}])
        self.assertEqual(result["report_parse_rate"], 0.0)
        for metric, count in (
            ("citation_reference_validity_rate", "citation_reference_validity_record_count"),
            ("structurally_grounded_claim_rate", "structurally_grounded_record_count"),
            ("counterevidence_workflow_complete_rate", "counterevidence_workflow_record_count"),
            ("knowledge_lexical_bridge_rate", "knowledge_lexical_bridge_record_count"),
            ("unsupported_claim_rate", "unsupported_claim_record_count"),
            ("semantic_entailment_verified_rate", "semantic_entailment_record_count"),
        ):
            with self.subTest(metric=metric):
                self.assertIsNone(result[metric])
                self.assertEqual(result[count], 0)

    def test_unknown_and_not_applicable_statuses_do_not_earn_credit(self):
        records = [
            {"knowledge_citation_audit": {"status": status},
             "retrieval_audit": {"outcome": outcome},
             "claim_evidence_audit": {"claims": [{}]},
             "claim_support_audit": {"claims": [
                 {"knowledge_ids": ["k1"], "status": "missing_material"}]}}
            for status, outcome in (("no_citations", "not_used"), ("unknown", "unknown"))
        ]
        result = investigation_metrics(records)
        self.assertIsNone(result["citation_reference_validity_rate"])
        self.assertIsNone(result["counterevidence_workflow_complete_rate"])
        self.assertIsNone(result["structurally_grounded_claim_rate"])
        self.assertIsNone(result["knowledge_lexical_bridge_rate"])

    def test_missing_records_do_not_dilute_observed_failures(self):
        result = investigation_metrics([{}, {
            "knowledge_citation_audit": {"status": "invalid_references"},
            "retrieval_audit": {"outcome": "counterevidence_not_checked"},
            "claim_evidence_audit": {
                "status": "unsupported_claims", "claim_count": 2,
                "unsupported_claim_indexes": [0],
                "claims": [{"structurally_supported": False},
                           {"structurally_supported": True}],
            },
            "claim_support_audit": {"claims": [
                {"knowledge_ids": ["k1"], "status": "no_lexical_bridge"}]},
            "claim_entailment_audit": {"semantic_entailment_verified": False},
        }])
        self.assertEqual(result["record_count"], 2)
        self.assertEqual(result["citation_reference_validity_rate"], 0.0)
        self.assertEqual(result["citation_reference_validity_record_count"], 1)
        self.assertEqual(result["counterevidence_workflow_complete_rate"], 0.0)
        self.assertEqual(result["counterevidence_workflow_record_count"], 1)
        self.assertEqual(result["structurally_grounded_claim_rate"], 0.5)
        self.assertEqual(result["unsupported_claim_rate"], 0.5)
        self.assertEqual(result["unsupported_claim_record_count"], 1)
        self.assertEqual(result["knowledge_lexical_bridge_rate"], 0.0)
        self.assertEqual(result["semantic_entailment_verified_rate"], 0.0)
        self.assertEqual(result["semantic_entailment_record_count"], 1)

    def test_semantic_verification_uses_actual_entailment_audit(self):
        result = investigation_metrics([{
            "claim_support_audit": {"semantic_entailment_verified": False},
            "claim_entailment_audit": {"semantic_entailment_verified": True},
        }])
        self.assertEqual(result["semantic_entailment_verified_rate"], 1.0)
        self.assertEqual(result["semantic_entailment_record_count"], 1)

    def test_lexical_screen_cannot_supply_semantic_verification(self):
        result = investigation_metrics([{
            "claim_support_audit": {"semantic_entailment_verified": True},
        }, {"claim_entailment_audit": {"semantic_entailment_verified": "false"}}])
        self.assertIsNone(result["semantic_entailment_verified_rate"])
        self.assertEqual(result["semantic_entailment_record_count"], 0)

    def test_counterevidence_outcomes(self):
        for outcome, expected in (
            ("balanced", 1.0), ("counterevidence_not_checked", 0.0),
            ("counterevidence_incomplete", 0.0), ("retrieval_incomplete", 0.0),
        ):
            with self.subTest(outcome=outcome):
                result = investigation_metrics([{"retrieval_audit": {"outcome": outcome}}])
                self.assertEqual(result["counterevidence_workflow_complete_rate"], expected)

    def test_no_match_requires_recorded_counterevidence_search(self):
        for outcome in ("knowledge_gap", "exhausted_no_match"):
            for performed in (None, False, True):
                with self.subTest(outcome=outcome, performed=performed):
                    audit = {"outcome": outcome}
                    if performed is not None:
                        audit["counterevidence_search_performed"] = performed
                    result = investigation_metrics([{"retrieval_audit": audit}])
                    self.assertEqual(result["counterevidence_workflow_complete_rate"], performed)

    def test_invalid_empty_or_incomplete_claim_audits_have_no_unsupported_rate(self):
        for audit in (
            {"status": "invalid_report", "claim_count": 0, "unsupported_claim_indexes": []},
            {"status": "workflow_incomplete", "claim_count": 0, "unsupported_claim_indexes": []},
            {"status": "structurally_grounded", "claim_count": 1},
            {"claim_count": 1, "unsupported_claim_indexes": []},
        ):
            with self.subTest(audit=audit):
                result = investigation_metrics([{"claim_evidence_audit": audit}])
                self.assertIsNone(result["unsupported_claim_rate"])
                self.assertEqual(result["unsupported_claim_record_count"], 0)

    def test_explicit_successful_audits_remain_successful(self):
        result = investigation_metrics([{
            "knowledge_citation_audit": {"status": "references_present"},
            "retrieval_audit": {"outcome": "balanced"},
            "claim_evidence_audit": {
                "status": "structurally_grounded", "claim_count": 1,
                "unsupported_claim_indexes": [],
                "claims": [{"structurally_supported": True}],
            },
            "claim_support_audit": {"claims": [
                {"knowledge_ids": ["k1"], "status": "semantic_review_required"}]},
            "claim_entailment_audit": {"semantic_entailment_verified": True},
        }])
        self.assertEqual(result["citation_reference_validity_rate"], 1.0)
        self.assertEqual(result["structurally_grounded_claim_rate"], 1.0)
        self.assertEqual(result["counterevidence_workflow_complete_rate"], 1.0)
        self.assertEqual(result["knowledge_lexical_bridge_rate"], 1.0)
        self.assertEqual(result["unsupported_claim_rate"], 0.0)
        self.assertEqual(result["semantic_entailment_verified_rate"], 1.0)

    def test_no_records_preserves_default_scorecard_contract(self):
        result = investigation_metrics([])
        self.assertEqual(result["record_count"], 0)
        self.assertNotIn("semantic_entailment_verified_rate", result)
        self.assertIn("No real investigation outputs", result["note"])

    def test_partial_or_malformed_structural_claims_make_whole_record_unknown(self):
        for claims in (
            [{"structurally_supported": True}, {}],
            [{"structurally_supported": True}, {"structurally_supported": 1}],
            [{"structurally_supported": True}, None],
            {"structurally_supported": True},
        ):
            with self.subTest(claims=claims):
                result = investigation_metrics([{"claim_evidence_audit": {"claims": claims}}])
                self.assertIsNone(result["structurally_grounded_claim_rate"])
                self.assertEqual(result["structurally_grounded_record_count"], 0)

    def test_partial_lexical_bridge_makes_whole_record_unknown(self):
        good = {"knowledge_ids": ["k1"], "status": "semantic_review_required"}
        for unknown in (
            {"knowledge_ids": ["k2"]},
            {"knowledge_ids": ["k2"], "status": "missing_material"},
            {"knowledge_ids": "k2", "status": "semantic_review_required"},
            {"knowledge_ids": [None], "status": "semantic_review_required"},
            {}, None,
        ):
            with self.subTest(unknown=unknown):
                result = investigation_metrics([{
                    "claim_support_audit": {"claims": [good, unknown]},
                }])
                self.assertIsNone(result["knowledge_lexical_bridge_rate"])
                self.assertEqual(result["knowledge_lexical_bridge_record_count"], 0)

    def test_explicit_non_knowledge_claim_is_not_missing_lexical_audit(self):
        result = investigation_metrics([{"claim_support_audit": {"claims": [
            {"knowledge_ids": ["k1"], "status": "semantic_review_required"},
            {"knowledge_ids": [], "status": "no_knowledge_material"},
        ]}}])
        self.assertEqual(result["knowledge_lexical_bridge_rate"], 1.0)
        self.assertEqual(result["knowledge_lexical_bridge_record_count"], 1)

    def test_malformed_unsupported_counts_and_indexes_are_unknown(self):
        for count, indexes in (
            (1, [0, 1]), (1, [0, 0]), (1, [-1]),
            (1, [True]), (1, [False]), (1, [0.0]), (1, ["0"]),
            (1, [None]), (1, [[0]]), (1, {"0": True}),
            (True, []), (False, []), (1.0, []), ("1", []),
            (0, []), (-1, []), (None, []),
        ):
            with self.subTest(count=count, indexes=indexes):
                result = investigation_metrics([{"claim_evidence_audit": {
                    "status": "unsupported_claims", "claim_count": count,
                    "unsupported_claim_indexes": indexes,
                }}])
                self.assertIsNone(result["unsupported_claim_rate"])
                self.assertEqual(result["unsupported_claim_record_count"], 0)

    def test_claim_rates_are_macro_averages_with_explicit_note(self):
        records = []
        for count, supported in ((1, True), (3, False)):
            records.append({
                "claim_evidence_audit": {
                    "status": "structurally_grounded" if supported else "unsupported_claims",
                    "claim_count": count,
                    "unsupported_claim_indexes": [] if supported else list(range(count)),
                    "claims": [{"structurally_supported": supported} for _ in range(count)],
                },
                "claim_support_audit": {"claims": [
                    {"knowledge_ids": ["k1"], "status": (
                        "semantic_review_required" if supported else "no_lexical_bridge")}
                    for _ in range(count)]},
            })
        result = investigation_metrics(records)
        self.assertEqual(result["structurally_grounded_claim_rate"], 0.5)
        self.assertEqual(result["knowledge_lexical_bridge_rate"], 0.5)
        self.assertEqual(result["unsupported_claim_rate"], 0.5)
        self.assertIn("macro", result["claim_rate_aggregation_note"])
        self.assertIn("not pooled claim-level", result["claim_rate_aggregation_note"])


if __name__ == "__main__":
    unittest.main()
