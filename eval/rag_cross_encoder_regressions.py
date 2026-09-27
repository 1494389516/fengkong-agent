"""Cross-encoder integration regressions without downloading a model."""
import os
import tempfile
import unittest
from unittest.mock import patch

from agent.rag.store import ingest, search


class FakeReranker:
    identity = "fake-cross-encoder"

    def score(self, query, passages):
        # Prefer caveat material for uncertainty queries and implementation
        # material for source-code questions. This tests wiring, not ML quality.
        scores = []
        for passage in passages:
            score = 0.0
            if any(x in query for x in ("能否", "误报", "合法")) and "误报与能力边界" in passage:
                score += 10.0
            if any(x in query for x in ("实现", "源码", "代码")) and "实现与信号含义" in passage:
                score += 10.0
            if "SensorReplayDetector" in query and "SensorReplayDetector" in passage:
                score += 2.0
            scores.append(score)
        return scores


class BrokenReranker:
    def score(self, query, passages):
        raise RuntimeError("offline")


class CrossEncoderRegression(unittest.TestCase):
    def test_cross_encoder_is_second_stage_only(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"FK_DATA_DIR": directory}):
            ingest("knowledge")
            result = search(
                "SensorReplayDetector 当前代码实现用了什么",
                platform="ios", top_k=5, reranker=FakeReranker())
            self.assertIn("cross_encoder", result["mode"])
            self.assertEqual(result["hits"][0]["knowledge_id"], "sdk_sensor_replay")
            self.assertEqual(result["hits"][0]["section"], "实现与信号含义")

            no_match = search(
                "zzzz_unknown_signal_7821", platform="ios",
                top_k=5, reranker=FakeReranker())
            self.assertEqual(no_match["hits"], [])
            self.assertNotIn("cross_encoder", no_match["mode"])

    def test_failure_falls_back_explicitly(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"FK_DATA_DIR": directory}):
            ingest("knowledge")
            baseline = search("DebuggerDetector 合法调试能否等同云手机",
                              platform="ios", top_k=5)
            failed = search("DebuggerDetector 合法调试能否等同云手机",
                            platform="ios", top_k=5, reranker=BrokenReranker())
            self.assertEqual(
                [(x["knowledge_id"], x["section"]) for x in failed["hits"]],
                [(x["knowledge_id"], x["section"]) for x in baseline["hits"]])
            self.assertIn("cross-encoder unavailable or invalid", failed["warning"])

    def test_disabled_provider_has_no_optional_dependency(self):
        with patch.dict(os.environ, {"FK_RAG_RERANK_ENABLED": "0"}):
            from agent.rag.cross_encoder import configured_reranker
            self.assertIsNone(configured_reranker())


if __name__ == "__main__":
    unittest.main()
