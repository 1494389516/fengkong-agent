# -*- coding: utf-8 -*-
import hashlib
import hmac
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


class PrivacyTests(unittest.TestCase):
    def test_privacy_is_default_on_and_structured_fields_are_tokenized(self):
        from agent.privacy import Tokenizer, privacy_enabled
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertTrue(privacy_enabled())
        t = Tokenizer(salt="test")
        raw = {"uid": "customer@example.com", "reported_uid": "custom-account-7",
               "nested": {"device_id": "550e8400-e29b-41d4-a716-446655440000"}}
        safe = t.tokenize_data(raw)
        self.assertNotIn("customer@example.com", json.dumps(safe))
        self.assertTrue(safe["uid"].startswith("UID_"))
        self.assertTrue(safe["reported_uid"].startswith("UID_"))
        self.assertTrue(safe["nested"]["device_id"].startswith("DEV_"))

    def test_public_llm_refuses_explicit_privacy_disable(self):
        from agent import llm
        env = {"DEEPSEEK_API_KEY": "test", "FK_PRIVACY": "0"}
        with mock.patch.dict(os.environ, env, clear=True):
            with self.assertRaisesRegex(RuntimeError, "公网 LLM"):
                llm.load_config()


class CapabilityTests(unittest.TestCase):
    def test_registry_is_fully_classified_and_unknown_registration_fails(self):
        from agent.tools import _REGISTRY
        from agent.tools.capability import validate_registry
        validate_registry(_REGISTRY)
        with self.assertRaisesRegex(RuntimeError, "dummy_write"):
            validate_registry({**_REGISTRY, "dummy_write": {}})

    def test_dataset_export_requires_explicit_user_intent(self):
        from agent.tools import capability
        capability.set_user_text("帮我看看模型情况")
        try:
            denied = capability.enforce("build_dataset", True)
        finally:
            capability.clear_user_text()
        self.assertIn("execute blocked", denied)
        capability.set_user_text("请导出建模样本")
        try:
            self.assertEqual(capability.enforce("build_dataset", True), "")
        finally:
            capability.clear_user_text()


class IdempotencyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"FK_DATA_DIR": self.tmp.name}, clear=False)
        self.env.start()
        import serve
        serve._idemp.clear()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def test_concurrent_same_event_computes_once_and_payload_change_conflicts(self):
        import serve
        from agent.tools.idemp_store import IdempotencyConflict
        event = {"event_id": "evt-1", "uid": "u_1001", "type": "login", "ts": 1}
        calls = []

        def fake_compute(_event, _operator):
            calls.append(1)
            time.sleep(0.1)
            return {"action": "pass", "rules": [], "policy_version": 1,
                    "latency_ms": 1, "idempotent_replay": False}

        results = []
        with mock.patch.object(serve, "_compute", side_effect=fake_compute):
            threads = [threading.Thread(target=lambda: results.append(serve._decide(dict(event))))
                       for _ in range(4)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=3)
            self.assertEqual(len(calls), 1)
            self.assertEqual(len(results), 4)
            self.assertEqual(sum(bool(r["idempotent_replay"]) for r in results), 3)
            changed = {**event, "uid": "u_9999"}
            with self.assertRaises(IdempotencyConflict):
                serve._decide(changed)

    def test_disk_store_is_bounded(self):
        from agent.tools.idemp_store import complete, idemp_path
        with mock.patch.dict(os.environ, {"FK_IDEMP_MAX_RECORDS": "2"}, clear=False):
            for i in range(3):
                complete("key-%d" % i, {"action": "pass"}, "fp-%d" % i)
        records = json.loads(idemp_path().read_text(encoding="utf-8"))
        self.assertEqual(len(records), 2)

    def test_same_key_is_computed_once_across_processes(self):
        marker = Path(self.tmp.name) / "compute-marker"
        script = """
import os, time
from pathlib import Path
from agent.tools.idemp_store import claim, complete, lookup
key, input_fp = 'cross-process-key', 'same-payload'
with claim(key):
    if lookup(key, input_fp) is not None:
        print('replay')
    else:
        with open(os.environ['MARKER'], 'a', encoding='utf-8') as fh:
            fh.write('compute\\n')
        time.sleep(0.2)
        complete(key, {'action': 'pass'}, input_fp)
        print('compute')
"""
        env = dict(os.environ)
        env.update({"FK_DATA_DIR": self.tmp.name, "MARKER": str(marker),
                    "PYTHONPATH": str(ROOT)})
        procs = [subprocess.Popen([sys.executable, "-c", script], cwd=str(ROOT),
                                  env=env, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True)
                 for _ in range(2)]
        outputs = []
        for proc in procs:
            stdout, stderr = proc.communicate(timeout=5)
            self.assertEqual(proc.returncode, 0, stderr)
            outputs.append(stdout.strip())
        self.assertEqual(sorted(outputs), ["compute", "replay"])
        self.assertEqual(marker.read_text(encoding="utf-8").splitlines(), ["compute"])


class HttpServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        data_dir = Path(cls.tmp.name) / "data"
        shutil.copytree(ROOT / "data", data_dir)
        cls.log_path = Path(cls.tmp.name) / "serve.jsonl"
        cls.token = "test-bearer-token-at-least-16"
        cls.operator_secret = "test-operator-secret"
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            cls.port = sock.getsockname()[1]
        env = dict(os.environ)
        env.update({"FK_DATA_DIR": str(data_dir), "FK_SERVE_TOKEN": cls.token,
                    "FK_OPERATOR_HMAC_SECRET": cls.operator_secret,
                    "FK_SERVE_LOG_PATH": str(cls.log_path)})
        cls.proc = subprocess.Popen(
            [sys.executable, str(ROOT / "serve.py"), "--port", str(cls.port)],
            cwd=str(ROOT), env=env, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        for _ in range(50):
            try:
                if cls.request("/health", auth=False)[0] == 200:
                    break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("serve.py did not become ready")

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        cls.proc.wait(timeout=5)
        cls.tmp.cleanup()

    @classmethod
    def request(cls, path, payload=None, auth=True, headers=None):
        request_headers = {"Content-Type": "application/json"}
        if auth:
            request_headers["Authorization"] = "Bearer " + cls.token
        request_headers.update(headers or {})
        req = urllib.request.Request(
            "http://127.0.0.1:%d%s" % (cls.port, path),
            data=(json.dumps(payload).encode() if payload is not None else None),
            headers=request_headers)
        try:
            with urllib.request.urlopen(req, timeout=3) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_auth_validation_signed_operator_and_idempotency_conflict(self):
        self.assertEqual(self.request("/brief", auth=False)[0], 401)
        event = {"event_id": "http-1", "uid": "u_1001", "type": "login",
                 "ts": 1784099100}
        self.assertEqual(self.request("/decide", event, auth=False)[0], 401)
        self.assertEqual(self.request("/decide", {**event, "amount": "9.9"})[0], 400)
        self.assertEqual(self.request("/decide", {**event, "extra": float("nan")})[0], 400)
        self.assertEqual(self.request("/decide", event,
                                      headers={"X-Operator": "mallory"})[0], 401)

        ts = str(int(time.time()))
        operator = "eval_sso"
        message = "%s\n%s\nPOST\n/decide" % (ts, operator)
        signature = hmac.new(self.operator_secret.encode(), message.encode(),
                             hashlib.sha256).hexdigest()
        headers = {"X-Operator": operator, "X-Operator-Timestamp": ts,
                   "X-Operator-Signature": signature}
        code, first = self.request("/decide", event, headers=headers)
        self.assertEqual(code, 200)
        self.assertFalse(first["idempotent_replay"])
        self.assertEqual(self.request("/decide", {**event, "uid": "u_1002"})[0], 409)
        lineage = (Path(self.tmp.name) / "data" / "decision_lineage.jsonl").read_text()
        self.assertIn('"approver": "eval_sso"', lineage)

    def test_negative_content_length_is_rejected_without_reading_to_eof(self):
        request = ("POST /decide HTTP/1.1\r\nHost: localhost\r\n"
                   "Authorization: Bearer %s\r\nContent-Type: application/json\r\n"
                   "Content-Length: -1\r\n\r\n" % self.token).encode()
        with socket.create_connection(("127.0.0.1", self.port), timeout=2) as sock:
            sock.sendall(request)
            response = sock.recv(1024)
        self.assertIn(b" 400 ", response)


if __name__ == "__main__":
    unittest.main()
