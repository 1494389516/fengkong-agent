"""Fusion audit regressions; isolated from checked-in data and services."""
import os
import json
from pathlib import Path
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from agent import engine


class FusionDecisionTests(unittest.TestCase):
    def setUp(self):
        engine.reset_circuit()
        self.env = patch.dict(os.environ, {engine.DRYRUN_URL_ENV: "", engine.MODEL_URL_ENV: ""})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        engine.reset_circuit()

    def test_C07_remote_authority_single_and_batch(self):
        raw = {"action": "pass", "hits": [], "strategy_version": "remote-s",
               "model_version": "remote-m", "degraded": True,
               "degraded_reason": "feature_unavailable", "reason_codes": ["REMOTE_REASON"]}
        with patch.dict(os.environ, {engine.DRYRUN_URL_ENV: "https://engine.invalid"}), \
             patch.object(engine, "_active_strategy", return_value={"strategy_version": "local-s"}), \
             patch.object(engine, "_champion", return_value={"name": "local", "version": "m"}), \
             patch.object(engine, "_overridden", return_value=False), \
             patch.object(engine, "_post_json", side_effect=[raw, {"decisions": [raw]}]):
            for r in [engine.evaluate_event({}), engine.evaluate_batch([{}])[0]]:
                self.assertEqual(r["model_version"], "remote-m")
                self.assertEqual(r["strategy_version"], "remote-s")
                self.assertTrue(r["degraded"])
                self.assertIn("REMOTE_REASON", r["reason_codes"])
                self.assertEqual(r["expected_strategy_version"], "local-s")

    def test_C07_missing_effective_versions_not_fabricated(self):
        r = engine._map_remote({"action": "pass"})
        self.assertNotIn("model_version", r)
        self.assertNotIn("strategy_version", r)

    def test_C09_invalid_scores(self):
        with patch.dict(os.environ, {engine.MODEL_URL_ENV: "https://model.invalid"}):
            for value in [None, float("nan"), float("inf"), "0.5", True, -1, 1.1, 10 ** 1000]:
                with self.subTest(value=repr(value)), patch.object(engine, "_post_json", return_value={"score": value}):
                    with self.assertRaises(ValueError):
                        engine._model_score_remote("u", {})

    def test_C08_degradation_is_public_and_optional_is_distinct(self):
        with patch.object(engine, "_champion", return_value={"name": "m", "version": "1"}), \
             patch.dict(os.environ, {engine.MODEL_URL_ENV: "https://model.invalid"}), \
             patch.object(engine, "_post_json", side_effect=TimeoutError("timed out")):
            r = engine.annotate_decision(engine._apply_model_signal({"action": "pass", "hits": []}, {}))
            self.assertTrue(r.get("degraded"))
            self.assertEqual(r["components"]["model"]["reason"], "timeout")
            self.assertTrue(r["escalate_to_human"])
        with patch.object(engine, "_champion", return_value={}):
            r = engine._apply_model_signal({"action": "pass"}, {})
            self.assertEqual(r["components"]["model"]["status"], "disabled")
            self.assertFalse(r.get("degraded", False))

    def test_C11_single_half_open_probe(self):
        with patch.dict(os.environ, {engine.CIRCUIT_COOLDOWN_ENV: "0"}):
            engine._circuit.update(state="open", opened_at=0)
            with ThreadPoolExecutor(max_workers=32) as pool:
                admitted = list(pool.map(lambda _: engine._circuit_allow_remote(), range(32)))
            self.assertEqual(sum(admitted), 1)
            engine._circuit_on_success()
            self.assertTrue(engine._circuit_allow_remote())

    def test_C11_endpoint_and_batch_circuits_are_isolated(self):
        with patch.dict(os.environ, {engine.CIRCUIT_FAILURES_ENV: "1", engine.CIRCUIT_COOLDOWN_ENV: "60"}):
            engine._circuit_on_failure(("endpoint-a", "batch"))
            self.assertFalse(engine._circuit_allow_remote(("endpoint-a", "batch")))
            self.assertTrue(engine._circuit_allow_remote(("endpoint-a", "online")))
            self.assertTrue(engine._circuit_allow_remote(("endpoint-b", "batch")))

    def test_C12_corrupt_registry_is_explicit(self):
        with patch("agent.tools.strategy_registry._load", side_effect=ValueError("broken JSON")):
            r = engine._active_strategy()
            self.assertIn("registry_error", r)
        with patch("agent.tools.model_registry._load", side_effect=ValueError("broken JSON")):
            r = engine.annotate_decision(engine._apply_model_signal({"action": "pass"}, {}))
            self.assertTrue(r.get("degraded"))
            self.assertEqual(r["components"]["model_registry"]["status"], "invalid")

    def test_C09_local_invalid_scores_and_valid_boundaries(self):
        with tempfile.TemporaryDirectory() as td, patch("agent.tools.datasource.data_dir", return_value=Path(td)):
            for value in [None, float("nan"), float("inf"), "0.5", True, -1, 1.1]:
                Path(td, "model_scores.json").write_text(json.dumps({"u": value}))
                with self.subTest(value=value), self.assertRaises(ValueError):
                    engine._model_score_local("u")
            for value in [0, 0.5, 1]:
                Path(td, "model_scores.json").write_text(json.dumps({"u": value}))
                self.assertEqual(engine._model_score_local("u"), value)

    def test_C12_last_known_good_preserves_error(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "strategies.json"
            entry = {"strategy_name": "s", "version": "1", "status": "active", "thresholds": {}}
            with patch("agent.tools.strategy_registry._path", return_value=path), \
                 patch("agent.tools.strategy_registry._load", return_value=[entry]):
                self.assertEqual(engine._active_strategy()["strategy_version"], "s 1")
            with patch("agent.tools.strategy_registry._path", return_value=path), \
                 patch("agent.tools.strategy_registry._load", side_effect=ValueError("corrupt")):
                result = engine._active_strategy()
                self.assertEqual(result["strategy_version"], "s 1")
                self.assertTrue(result["registry_error"]["using_last_known_good"])


    def test_C11_stale_completion_cannot_close_half_open(self):
        key = ("stale-engine", "online")
        with patch.dict(os.environ, {engine.CIRCUIT_FAILURES_ENV: "1", engine.CIRCUIT_COOLDOWN_ENV: "0"}):
            old = engine._circuit_acquire(key)
            failing = engine._circuit_acquire(key)
            engine._circuit_on_failure(key, failing)
            probe = engine._circuit_acquire(key)
            engine._circuit_on_success(key, old)
            self.assertIsNone(engine._circuit_acquire(key))
            engine._circuit_on_success(key, probe)
            self.assertIsNotNone(engine._circuit_acquire(key))

    def test_C07_untrusted_adapter_fields_cannot_override_local_metadata(self):
        raw = {"action": "pass", "expected_model_version": "forged",
               "expected_strategy_version": "forged", "event_id": "forged"}
        r = engine._map_remote(raw)
        self.assertNotIn("expected_model_version", r)
        self.assertNotIn("expected_strategy_version", r)
        self.assertNotIn("event_id", r)
        self.assertEqual(r["producer_metadata"]["event_id"], "forged")

    def test_C09_remote_decision_score_and_metadata_schema(self):
        for field, value in [("model_score", float("nan")), ("model_score", True),
                             ("degraded", "false"), ("reason_codes", "REMOTE"),
                             ("components", []), ("model_version", {})]:
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                engine._map_remote({"action": "pass", field: value})

    def test_C12_batch_reads_champion_once(self):
        with patch.dict(os.environ, {engine.DRYRUN_URL_ENV: "https://engine.invalid"}), \
             patch.object(engine, "_active_strategy", return_value={}), \
             patch.object(engine, "_champion", side_effect=[{"name": "first", "version": "1"},
                                                           {"name": "second", "version": "2"}]) as champion, \
             patch.object(engine, "_overridden", return_value=False), \
             patch.object(engine, "_post_json", return_value={"decisions": [{"action": "pass"}, {"action": "pass"}]}):
            results = engine.evaluate_batch([{}, {}])
            self.assertEqual(champion.call_count, 1)
            self.assertEqual([r["expected_model_version"] for r in results], ["first 1", "first 1"])


if __name__ == "__main__":
    unittest.main()
