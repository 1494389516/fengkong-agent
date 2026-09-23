"""Regression cases for out-of-order graph events and invalidated projections.

Run with: python -m eval.graph_projection_regressions
"""
import os
import tempfile
import time
import unittest
from unittest.mock import patch

from agent.event_bus import event_bus
from agent.graph_risk import ingest_observation, lookup, refresh_dirty_devices


def observation(evidence_id, device, uid, recorded_at):
    return {
        "evidence_id": evidence_id, "tenant_id": "t", "app_id": "a",
        "device_id": device, "entity_generation": "g",
        "identity_trust": "server_bound", "uid": uid,
        "observed_at": recorded_at, "recorded_at": recorded_at,
    }


class GraphProjectionRegressions(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        env = patch.dict(os.environ, {"FK_DATA_DIR": self.tmp.name,
                                   "FK_GRAPH_ALGORITHM": "community_v1",
                                   "FK_GRAPH_SHADOW_ALGORITHM": ""})
        env.start()
        self.addCleanup(env.stop)

    def test_older_retry_cannot_roll_back_fresh_projection(self):
        base = time.time() - 10
        ingest_observation(observation("new1", "A", "u1", base + 2))
        ingest_observation(observation("new2", "A", "u2", base + 3))
        before = lookup("t", "a", "A", "g")
        ingest_observation(observation("old", "A", "u0", base + 1))
        after = lookup("t", "a", "A", "g")
        self.assertEqual(before["account_count"], 2)
        self.assertEqual(after["account_count"], 3)
        self.assertEqual(after["as_of"], before["as_of"])

    def test_new_device_invalidates_and_refreshes_old_neighbors(self):
        base = time.time() - 10
        ingest_observation(observation("a", "A", "shared", base + 1))
        for index in range(1, 4):
            ingest_observation(observation(f"b{index}", f"B{index}",
                                           "shared", base + index + 1))
        self.assertIsNone(lookup("t", "a", "A", "g"))
        refreshed = refresh_dirty_devices(limit=10)
        self.assertGreaterEqual(refreshed["refreshed"], 1)
        self.assertFalse(refreshed["failed"])
        graph = lookup("t", "a", "A", "g")
        self.assertEqual(graph["max_account_device_churn"], 4)
        self.assertIn("identity_churn", graph["risk_tags"])

    def test_expired_lease_cannot_acknowledge_or_fail(self):
        bus = event_bus()
        event = bus.publish("risk.evidence.accepted", "key", {"v": 1})
        expired = bus.claim("risk.evidence.accepted", limit=1,
                            lease_seconds=1, now=time.time() - 100)[0]
        self.assertFalse(bus.acknowledge(event.event_id, expired.lease_token))
        self.assertFalse(bus.fail(event.event_id, expired.lease_token, "late"))
        renewed = bus.claim("risk.evidence.accepted", limit=1)[0]
        self.assertTrue(bus.acknowledge(event.event_id, renewed.lease_token))

    def test_bounded_partial_graph_is_not_reported_current(self):
        base = time.time() - 10
        with patch("agent.graph_risk.MAX_ROWS", 2):
            for index in range(3):
                ingest_observation(observation(f"e{index}", "A", f"u{index}",
                                               base + index))
            self.assertIsNone(lookup("t", "a", "A", "g"))


if __name__ == "__main__":
    unittest.main()
