import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import serve


class StateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.env = mock.patch.dict(os.environ, {"FK_DATA_DIR": self.tmp.name,
            "FK_SERVE_LOG_PATH": self.tmp.name + "/decisions.jsonl"})
        self.env.start()
        self.addCleanup(self.env.stop)

    def event(self, n=1):
        return dict(event_id=str(n), uid="u", type="coupon_claim", ts=100+n,
                    ip="1.2.3.4", device_id="d")

    def test_g02_explicit_payload_kind_must_be_business_event(self):
        for source in ("legacy_client", "business"):
            for kind in ("sdk_report", "decision_request", "unknown", None, [], {}):
                with self.subTest(source=source, kind=kind):
                    self.assertTrue(serve._validate_event(
                        {**self.event(), "kind": kind}, now=101, source_kind=source))
            self.assertEqual(serve._validate_event(self.event(), now=101, source_kind=source), "")
            self.assertEqual(serve._validate_event(
                {**self.event(), "kind": "business_risk_event"}, now=101, source_kind=source), "")

    def test_c15_malformed_type_and_huge_number_are_validation_errors(self):
        for update in ({"type": []}, {"ts": 10**1000}, {"amount": 10**1000}):
            self.assertTrue(serve._validate_event({**self.event(), **update}, now=101))

    def test_g01_next_request_reads_history_once(self):
        from agent.tools.featurelib import account_features
        seen = []
        def compute(event, operator):
            f = account_features("u", as_of_ts=event["ts"])
            seen.append(f.get("coupon_claims", 0))
            return {"action": "pass", "rules": [], "policy_version": 1}
        with mock.patch.object(serve, "_compute", side_effect=compute):
            one = serve._decide(self.event())
            replay = serve._decide(self.event())
            two = serve._decide(self.event(2))
        self.assertEqual(seen, [0, 1])
        self.assertEqual(one["decision_id"], replay["decision_id"])
        self.assertNotEqual(one["decision_id"], two["decision_id"])

    def test_c13_atomic_commit_fault_and_recovery(self):
        from agent.tools import online_store
        def fault(stage):
            if stage == "before_commit":
                raise RuntimeError("injected crash")
        with mock.patch.object(serve, "_compute", return_value={"action": "pass"}), \
             mock.patch.object(online_store, "_fault", side_effect=fault):
            with self.assertRaises(RuntimeError):
                serve._decide(self.event())
        with online_store.connect() as db:
            for table in ("decisions", "events", "outbox"):
                self.assertEqual(db.execute("SELECT count(*) FROM " + table).fetchone()[0], 0)
        with mock.patch.object(serve, "_compute", return_value={"action": "review"}):
            result = serve._decide(self.event())
        with mock.patch.object(serve, "_compute", side_effect=AssertionError("recomputed")):
            self.assertEqual(result["decision_id"], serve._decide(self.event())["decision_id"])

    def test_g02_scopes_and_g04_trusted_late_business_time(self):
        seen = []
        def compute(event, operator):
            seen.append(event)
            return {"action": "pass"}
        with mock.patch.object(serve, "_compute", side_effect=compute):
            a = serve._decide(self.event(), scope=("tenant-a", "app"),
                              source_kind="business", received_at=500)
            b = serve._decide(self.event(), scope=("tenant-b", "app"),
                              source_kind="business", received_at=500)
        self.assertNotEqual(a["decision_id"], b["decision_id"])
        self.assertEqual(seen[0]["ts"], 101)
        self.assertEqual(seen[0]["received_at"], 500)

    def test_c14_corrupt_legacy_store_fails_closed(self):
        from agent.tools.idemp_store import lookup, idemp_path
        idemp_path().write_text("{broken")
        with self.assertRaises(ValueError):
            lookup("x")

    def test_c14_online_does_not_silently_discard_legacy_idempotency(self):
        from agent.tools.idemp_store import complete
        complete("legacy-key", {"action": "review"}, "legacy-fingerprint")
        with mock.patch.object(serve, "_compute", return_value={"action": "pass"}), \
             self.assertRaisesRegex(RuntimeError, "migration"):
            serve._decide(self.event())

    def test_c14_capacity_cannot_evict_live_record(self):
        from agent.tools.idemp_store import complete, lookup
        with mock.patch.dict(os.environ, {"FK_IDEMP_MAX_RECORDS": "1"}):
            complete("a", {"action": "review"}, "a")
            with self.assertRaises(RuntimeError):
                complete("b", {"action": "pass"}, "b")
            self.assertEqual(lookup("a", "a")["action"], "review")

    def test_g04_validation_uses_authenticated_source_not_body_claim(self):
        late = self.event()
        self.assertEqual(serve._validate_event(late, now=5000, source_kind="business"), "")
        self.assertTrue(serve._validate_event(late, now=5000))
        self.assertTrue(serve._validate_event({**late, "source_kind": "business"}, now=101))
        self.assertTrue(serve._validate_event({**late, "tenant_id": "forged"}, now=101))
        self.assertTrue(serve._validate_event({**late, "server_aggregates": {}}, now=101))

    def test_c13_crash_after_commit_replays_without_recomputation(self):
        from agent.tools import online_store
        def fault(stage):
            if stage == "after_commit":
                raise RuntimeError("crash after commit")
        with mock.patch.object(serve, "_compute", return_value={"action": "review"}), \
             mock.patch.object(online_store, "_fault", side_effect=fault):
            with self.assertRaises(RuntimeError):
                serve._decide(self.event())
        with mock.patch.object(serve, "_compute", side_effect=AssertionError("recompute")):
            result = serve._decide(self.event())
        self.assertTrue(result["idempotent_replay"])
        self.assertEqual(result["action"], "review")

    def test_g04_authenticated_http_business_ingress(self):
        import threading
        import urllib.request
        import urllib.error
        from http.server import ThreadingHTTPServer
        server = ThreadingHTTPServer(("127.0.0.1", 0), serve.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        seen = []
        def compute(event, operator):
            seen.append(event)
            return {"action": "review"}
        try:
            with mock.patch.dict(os.environ, {"FK_SERVE_TOKEN": "trusted-business-token",
                 "FK_SERVE_SOURCE_KIND": "business", "FK_SERVE_TENANT": "t", "FK_SERVE_APP": "a"}), \
                 mock.patch.object(serve, "_compute", side_effect=compute):
                request = urllib.request.Request("http://127.0.0.1:%s/decide" % server.server_port,
                    data=json.dumps(self.event()).encode(), headers={"Content-Type": "application/json",
                    "Authorization": "Bearer trusted-business-token"})
                with urllib.request.urlopen(request, timeout=3) as response:
                    public = json.load(response)
                self.assertEqual(public["tenant_id"], "t")
                self.assertEqual(seen[0]["ts"], 101)
                self.assertGreater(seen[0]["received_at"], seen[0]["ts"])
                request.data = json.dumps({**self.event(2), "kind": "sdk_report"}).encode()
                with self.assertRaises(urllib.error.HTTPError) as error:
                    urllib.request.urlopen(request, timeout=3)
                self.assertEqual(error.exception.code, 400)
                self.assertEqual(len(seen), 1)
                request.data = json.dumps({**self.event(), "tenant_id": "forged"}).encode()
                with self.assertRaises(urllib.error.HTTPError) as error:
                    urllib.request.urlopen(request, timeout=3)
                self.assertEqual(error.exception.code, 400)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(3)
