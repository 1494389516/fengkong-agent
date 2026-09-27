"""Hard/adversarial RAG quality regressions.

Uses only reviewed checked-in knowledge. It measures retrieval/reranking contracts,
not fraud detection quality or semantic entailment.
"""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent.rag.store import ingest, search
from agent.rag.support import screen_claim, audit_report_support


class RAGQualityRegression(unittest.TestCase):
    def test_hard_rerank_cases(self):
        cases = [json.loads(line) for line in
                 Path("eval/rag/hard_cases.jsonl").read_text(encoding="utf-8").splitlines()
                 if line.strip()]
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"FK_DATA_DIR": directory}):
            ingest("knowledge")
            for case in cases:
                with self.subTest(query=case["query"]):
                    result = search(case["query"], platform=case["platform"], top_k=5)
                    self.assertIn("rerank", result["mode"] if result["hits"] else "rerank")
                    if case["expected_knowledge_id"] is None:
                        self.assertEqual(result["hits"], [])
                        continue
                    self.assertTrue(result["hits"])
                    top = result["hits"][0]
                    self.assertEqual(top["knowledge_id"], case["expected_knowledge_id"])
                    self.assertEqual(top["section"], case["expected_section"])

    def test_support_screen_is_conservative(self):
        material = [{"title": "传感器回放命名与计时代理信号",
                     "section": "误报与能力边界",
                     "text": "系统负载、计时器分辨率等正常因素需要实验排除。",
                     "caveats": "不能把这个信号写成已经发现传感器录制回放。",
                     "applicability": "仅解释固定源码提交。"}]
        related = screen_claim("系统负载可能影响该计时代理信号，不能单独证明传感器回放。", material)
        self.assertEqual(related["status"], "semantic_review_required")
        self.assertFalse(related["semantic_entailment_verified"])
        unrelated = screen_claim("该账号已经完成跨境洗钱并确认团伙身份。", material)
        self.assertEqual(unrelated["status"], "no_lexical_bridge")

    def test_report_support_flags_unrelated_citation(self):
        report = {"claims": [{
            "statement": "该账号已经完成跨境洗钱并确认团伙身份。",
            "knowledge_citations": ["[K:k1]"]
        }]}
        result = audit_report_support(report, {"k1": {
            "title": "调试器与断点检测", "section": "误报与能力边界",
            "text": "合法开发调试也可能命中。", "caveats": "", "applicability": ""
        }})
        self.assertEqual(result["status"], "lexical_gap")
        self.assertEqual(result["no_lexical_bridge_claim_indexes"], [0])
        self.assertFalse(result["semantic_entailment_verified"])


if __name__ == "__main__":
    unittest.main()
