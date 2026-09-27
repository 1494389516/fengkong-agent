"""Claim/evidence graph regressions."""
import unittest

from agent.rag.claim_graph import build_claim_evidence_graph


class ClaimEvidenceGraphRegression(unittest.TestCase):
    def test_only_server_registered_evidence_becomes_nodes(self):
        report = {"claims": [{
            "statement": "fixture",
            "role": "finding",
            "confidence": "medium",
            "event_evidence": ["event:e1", "event:missing"],
            "knowledge_citations": ["[K:k1]", "[K:missing]"],
        }]}
        graph = build_claim_evidence_graph(
            report,
            {"event:e1": {"kind": "event_fact"}},
            {"k1": {"source": "fixture", "section": "边界", "content_hash": "abc"}},
            {"claims": [{"index": 0, "status": "semantic_review_required",
                         "semantic_entailment_verified": False}]},
        )
        ids = {node["id"] for node in graph["nodes"]}
        self.assertIn("claim:0", ids)
        self.assertIn("event:e1", ids)
        self.assertIn("knowledge:k1", ids)
        self.assertNotIn("event:missing", ids)
        self.assertNotIn("knowledge:missing", ids)
        self.assertEqual(len(graph["unresolved_refs"]), 2)
        self.assertEqual(graph["status"], "unresolved_references")
        self.assertFalse(next(n for n in graph["nodes"] if n["id"] == "claim:0")
                         ["semantic_entailment_verified"])

    def test_counterevidence_role_is_preserved(self):
        graph = build_claim_evidence_graph(
            {"claims": [{"role": "counterevidence", "confidence": "medium",
                         "event_evidence": [], "knowledge_citations": ["[K:k1]"]}]},
            {}, {"k1": {"source": "fixture", "section": "误报与能力边界",
                        "content_hash": "abc"}},
        )
        claim = next(node for node in graph["nodes"] if node["kind"] == "claim")
        self.assertEqual(claim["role"], "counterevidence")
        self.assertEqual(graph["status"], "ok")


if __name__ == "__main__":
    unittest.main()
