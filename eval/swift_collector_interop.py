"""Consume native Swift uploads unchanged; never re-sign them in Python."""
import base64
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import unittest

from agent.collector import ingest
from agent.contracts.report_contract import verify_upload_with_base_key
from agent.privacy import Tokenizer
from agent.tenancy import data_context
from eval import rag_sdk_evidence_regressions as synthetic
from scripts.run_swift_collector import SDK_SHA


class SwiftCollectorInterop(unittest.TestCase):
    def test_native_uploads(self):
        path = Path(os.environ["FK_SWIFT_WIRE"])
        raw = path.read_bytes()
        provenance = json.loads(path.with_suffix(".provenance.json").read_text())
        self.assertEqual(provenance["sdk_sha"], SDK_SHA)
        self.assertEqual(provenance["wire_sha256"], hashlib.sha256(raw).hexdigest())
        rows = [json.loads(line) for line in raw.splitlines()]
        self.assertEqual(len(rows), 6)
        self.assertEqual({(r["sig_ver"], r.get("field_mapping_version", "")) for r in rows},
                         {(v, m) for v in ("v2", "v3") for m in ("", "m1", "m2")})
        for upload in rows:
            with self.subTest(version=upload["sig_ver"], mapping=upload.get("field_mapping_version")):
                fixture = synthetic.SDKEvidenceRegression()
                fixture.setUp()
                try:
                    fixture.now = upload["ts"] / 1000 + 0.001
                    attrs = {**fixture.ctx.attributes,
                        "field_mappings": {**fixture.attrs["field_mappings"], "m2": {"xg": "sg"}},
                        "field_mapping_scopes": {"m1": "all", "m2": "topLevel"}}
                    fixture.ctx = replace(fixture.ctx, attributes=attrs)
                    self.assertTrue(verify_upload_with_base_key(upload, b"k" * 32))
                    fixture.upload = lambda *args, **kwargs: dict(upload)
                    result = fixture.evidence({})
                    view = Tokenizer(salt="interop").project_tool_result("get_event_evidence", result)
                    projection = view["sdk_observations"][0]["sdk_signal_evidence"]
                    self.assertEqual(projection["status"], "available")
                    self.assertEqual([s["state"] for s in projection["signals"]], [
                        {"type": "hard", "detected": False}, {"type": "hard", "detected": True},
                        {"type": "soft", "confidence": 0.4}, {"type": "serverRequired"},
                        {"type": "unavailable"}, {"type": "tampered"}, {"type": "unspecified"}])
                    self.assertNotIn("PRIVATE", json.dumps(view))
                    self.assertNotIn("private_signal", json.dumps(view))
                    self.assertEqual(len([r for r in result["evidence_registry"] if r["kind"] == "sdk_signal"]), 7)
                    replay = ingest(upload, fixture.ctx, now=fixture.now)
                    self.assertTrue(replay["idempotent_replay"])
                    with sqlite3.connect(fixture.root / "online.sqlite3") as db:
                        self.assertEqual(db.execute("SELECT raw_payload FROM evidence").fetchone()[0],
                                         base64.b64decode(upload["payload_json"]))
                        self.assertEqual(db.execute("SELECT COUNT(*) FROM evidence").fetchone()[0], 1)
                        self.assertEqual(db.execute("SELECT COUNT(*) FROM integration_events").fetchone()[0], 1)
                    with self.assertRaises(ValueError):
                        ingest({**upload, "signature": "0" * 64}, fixture.ctx, now=fixture.now)
                    with self.assertRaises(PermissionError):
                        ingest(upload, replace(fixture.ctx, app="other"), now=fixture.now)
                    # Real durable consumer boundary: one claim, fenced acknowledgement.
                    from agent.event_bus import event_bus
                    with data_context(fixture.ctx):
                        claimed = event_bus().claim("risk.evidence.accepted")
                        self.assertEqual(len(claimed), 1)
                        event = claimed[0]
                        self.assertFalse(event_bus().acknowledge(event.event_id, "wrong-token"))
                        self.assertTrue(event_bus().acknowledge(event.event_id, event.lease_token))
                        self.assertEqual(event_bus().claim("risk.evidence.accepted"), [])
                    # Reuse the actual scripted worker integration with native bytes.
                    # This verifies provenance plumbing, not a real model's accuracy.
                    fixture.test_simulated_worker_report_persists_signal_provenance()
                finally:
                    fixture.doCleanups()


if __name__ == "__main__":
    unittest.main()
