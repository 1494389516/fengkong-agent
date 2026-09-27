# -*- coding: utf-8 -*-
"""Contract regressions for the independent entailment gate.

These tests validate wiring/fail-closed behavior only. They do not claim that a
real NLI/LLM evaluator is accurate; use rag_entailment_calibration.py with a
reviewed labeled set for that.
"""
import unittest

from agent.rag.entailment import evaluate_report_entailment


class FakeEvaluator:
    evaluator_id = "fake-contract"
    calibrated = True

    def __init__(self, label):
        self.label = label

    def evaluate(self, claim, premise):
        return {"label": self.label, "confidence": 0.9, "rationale": "contract fixture"}


class EntailmentGateRegression(unittest.TestCase):
    def setUp(self):
        self.report = {"claims": [{
            "statement": "合法开发调试可能触发调试器信号，单独命中不足以证明恶意。",
            "knowledge_citations": ["[K:k1]"],
        }]}
        self.material = {"k1": {
            "title": "DebuggerDetector", "section": "误报与能力边界",
            "text": "合法开发调试可能命中该信号。",
            "caveats": "单一信号不能证明恶意。", "applicability": "iOS",
        }}

    def test_supported_calibrated_passes(self):
        result = evaluate_report_entailment(
            self.report, self.material, evaluator=FakeEvaluator("SUPPORTED"))
        self.assertEqual(result["grounding_gate"], "PASS")
        self.assertTrue(result["semantic_entailment_verified"])

    def test_contradiction_fails_closed(self):
        result = evaluate_report_entailment(
            self.report, self.material, evaluator=FakeEvaluator("CONTRADICTED"))
        self.assertEqual(result["grounding_gate"], "REVIEW")
        self.assertEqual(result["blocking_claim_indexes"], [0])
        self.assertFalse(result["semantic_entailment_verified"])

    def test_uncalibrated_supported_is_not_verified(self):
        evaluator = FakeEvaluator("SUPPORTED")
        evaluator.calibrated = False
        result = evaluate_report_entailment(self.report, self.material, evaluator=evaluator)
        self.assertEqual(result["grounding_gate"], "REVIEW")
        self.assertFalse(result["semantic_entailment_verified"])

    def test_missing_material_is_insufficient(self):
        result = evaluate_report_entailment(
            self.report, {}, evaluator=FakeEvaluator("SUPPORTED"))
        self.assertEqual(result["claims"][0]["label"], "INSUFFICIENT")
        self.assertEqual(result["grounding_gate"], "REVIEW")


if __name__ == "__main__":
    unittest.main()
