#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Authenticated Collector and decision HTTP entrypoints.

POST /reports stores verified SDK evidence; POST /decisions consumes a typed
DecisionRequest; POST /decide retains the legacy business-event adapter.
GET /cases and /evidence/{id} require scoped investigator credentials.
Attestation enrollment and assertion challenges have dedicated endpoints.

FK_AUTH_CONFIG binds every credential to tenant/app/dataset and permissions.
SDK reports never reach the LLM. SQLite commits business decisions, idempotency,
events and outbox atomically; JSONL/case projections are recoverable.
Anonymous /health exposes liveness only in configured deployments.
Legacy FK_SERVE_TOKEN mode remains for explicit single-tenant compatibility.
"""
import argparse
import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import socket
import threading
import time
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LOG_PATH = ROOT / "out" / "serve_decisions.jsonl"
MAX_BODY = 64 * 1024
MAX_UID_LEN = 128
MAX_EVENT_ID_LEN = 256
MAX_STRING_LEN = 2048
REQUEST_TIMEOUT = 5.0
EVENT_MAX_AGE_SECONDS = 300.0
EVENT_MAX_FUTURE_SECONDS = 30.0
EVENT_TYPES = {"login", "coupon_claim", "order"}
_mu = threading.Lock()
_idemp: OrderedDict = OrderedDict()
_IDEMP_CACHE_MAX = 2048


def _public_view(decision: dict, replay: bool) -> dict:
    public = {k: decision.get(k) for k in (
        "action", "rules", "policy_version", "latency_ms",
        "reason_codes", "escalate_to_human", "degraded",
        "agent_cannot_override", "decision_combine", "decision_id",
        "business_event_id", "tenant_id", "app_id", "feature_snapshot_id",
        "strategy_version", "model_version", "component_status", "components",
        "degraded_reason", "producer_metadata", "effective_versions",
        "expected_strategy_version", "expected_model_version",
        "runtime_activation_id", "runtime_bundle_versions")}
    public["idempotent_replay"] = replay
    return public


def _replay(public: dict) -> dict:
    out = dict(public)
    out["idempotent_replay"] = True
    out["latency_ms"] = 0.0
    return out


def _compute(event: dict, operator: str) -> dict:
    from agent.tools.datasource import append_jsonl
    from agent.tools.lineage import write_lineage
    from agent.tools.rules import rule_eval
    t0 = time.time()
    # 在线判定只用服务端接收时间计算时序特征；客户端上报时间仅作审计字段，
    # 不能让调用方通过回拨 ts 把近期行为从速度窗口里抹掉。
    source_ts = event.get("_source_ts")
    evaluation_event = {k: v for k, v in event.items() if k != "_source_ts"}
    r = rule_eval(evaluation_event, use_current_policy=True)
    logged_event = dict(evaluation_event)
    if source_ts is not None:
        logged_event["source_ts"] = source_ts
    decision = {
        "ts": time.time(),
        "event": logged_event,
        "action": r["action"],
        "rules": sorted({h["rule_id"] for h in r["hits"]}),
        "hits": list(r.get("hits") or []),
        "policy_version": r["policy_version"],
        "strategy_version": r.get("strategy_version"),
        "model_version": r.get("model_version"),
        "model_score": r.get("model_score"),
        "source": r.get("source"),
        "degraded": bool(r.get("degraded")),
        "reason_codes": list(r.get("reason_codes") or []),
        "escalate_to_human": bool(r.get("escalate_to_human")),
        "agent_cannot_override": True,
        "decision_combine": r.get("decision_combine"),
        "combine_score": r.get("combine_score"),
        "latency_ms": round(1000 * (time.time() - t0), 1),
    }
    for key in ("component_status", "components", "degraded_reason", "producer_metadata",
                "effective_versions", "expected_strategy_version", "expected_model_version",
        "runtime_activation_id", "runtime_bundle_versions"):
        if key in r:
            decision[key] = r[key]
    return decision


def _decide(event: dict, operator: str = "serve", received_at: float = None,
            *, scope=None, source_kind="legacy_client", prepare=None) -> dict:
    from agent.tools import online_store
    scope = scope or (os.environ.get("FK_SERVE_TENANT", "local"),
                      os.environ.get("FK_SERVE_APP", "default"))
    # Legacy direct Python callers retain their historical timestamp behavior.
    if received_at is None:
        received_at = event["ts"]
    record, replay = online_store.decide(event, operator, _compute, scope=scope,
        source_kind=source_kind, received_at=received_at, prepare=prepare)
    try:
        online_store.export_outbox(_log_path())
        projection_status = "current"
    except (OSError, ValueError, __import__("sqlite3").Error):
        projection_status = "pending"
    public = _public_view(record, replay)
    public["audit_projection_status"] = projection_status
    return public


def _remember(key: str, input_fp: str, public: dict) -> None:
    with _mu:
        _idemp[key] = {"input_fingerprint": input_fp, "public": dict(public),
                       "completed_at": time.time()}
        _idemp.move_to_end(key)
        while len(_idemp) > _IDEMP_CACHE_MAX:
            _idemp.popitem(last=False)


def _serve_token() -> str:
    return os.environ.get("FK_SERVE_TOKEN", "")


def _log_path() -> Path:
    if os.environ.get("FK_AUTH_CONFIG"):
        from agent.tools.datasource import output_dir
        return output_dir() / "serve_decisions.jsonl"
    return Path(os.environ.get("FK_SERVE_LOG_PATH") or LOG_PATH)


def _valid_bearer(value: str) -> bool:
    token = _serve_token()
    return bool(token) and hmac.compare_digest(value or "", "Bearer " + token)


def _signed_operator(headers, method: str, path: str):
    operator = headers.get("X-Operator")
    if not operator:
        return os.environ.get("FK_OPERATOR") or "serve", ""
    if len(operator) > 128 or not re.fullmatch(r"[A-Za-z0-9._@+-]+", operator):
        return "", "invalid operator"
    secret = os.environ.get("FK_OPERATOR_HMAC_SECRET", "")
    ts = headers.get("X-Operator-Timestamp", "")
    supplied = headers.get("X-Operator-Signature", "")
    try:
        fresh = abs(time.time() - int(ts)) <= 60
    except (TypeError, ValueError):
        fresh = False
    if not secret or not fresh:
        return "", "unsigned or expired operator"
    message = "%s\n%s\n%s\n%s" % (ts, operator, method, path)
    expected = hmac.new(secret.encode("utf-8"), message.encode("utf-8"),
                        hashlib.sha256).hexdigest()
    if not hmac.compare_digest(supplied, expected):
        return "", "invalid operator signature"
    return operator, ""


def _finite_number(value) -> bool:
    try:
        return (isinstance(value, (int, float)) and not isinstance(value, bool)
                and math.isfinite(float(value)))
    except (ValueError, TypeError, OverflowError):
        return False


def _nonnegative_env_float(name: str, default: float) -> float:
    try:
        value = float(os.environ.get(name, str(default)) or default)
    except (TypeError, ValueError):
        return default
    return value if math.isfinite(value) and value >= 0 else default


def _validate_json_value(value, depth=0):
    if depth > 8:
        return "JSON 嵌套层数超过 8"
    if isinstance(value, str) and len(value) > MAX_STRING_LEN:
        return "字符串字段超过 %d 字符" % MAX_STRING_LEN
    if isinstance(value, int) and value.bit_length() > 1024:
        return "JSON integer exceeds supported range"
    if isinstance(value, float) and not math.isfinite(value):
        return "JSON 含 NaN/Infinity"
    if isinstance(value, dict):
        if len(value) > 64:
            return "JSON object 字段数超过 64"
        for nested in value.values():
            error = _validate_json_value(nested, depth + 1)
            if error:
                return error
    if isinstance(value, list):
        if len(value) > 256:
            return "JSON array 元素数超过 256"
        for nested in value:
            error = _validate_json_value(nested, depth + 1)
            if error:
                return error
    return ""


def _validate_event(event, now: float = None, *, source_kind="legacy_client"):
    if not isinstance(event, dict):
        return "body 必须是 JSON object"
    # Contract discriminator matches contracts/business-risk-event.schema.json.
    # Absence retains legacy business-event compatibility; an explicit other
    # envelope kind must never be laundered through an authenticated source.
    if "kind" in event and event["kind"] != "business_risk_event":
        return "kind 必须是 business_risk_event（不能提交 SDK 或决策请求封装）"
    reserved = {"tenant_id", "app_id", "source_kind", "server_aggregates", "server_verified_attestation",
                "received_at", "recorded_at", "decision_id", "_source_ts",
                "identity_trust", "entity_generation", "evidence_refs", "hardware_attributes"}
    if reserved.intersection(event):
        return "客户端不得提供服务端身份、证明或聚合字段"
    if source_kind not in ("legacy_client", "business"):
        return "不支持的认证事件源"
    shape_error = _validate_json_value(event)
    if shape_error:
        return shape_error
    for key, limit in (("event_id", MAX_EVENT_ID_LEN), ("uid", MAX_UID_LEN)):
        value = event.get(key)
        if not isinstance(value, str) or not value.strip() or len(value) > limit:
            return "%s 必须是 1~%d 字符串" % (key, limit)
    kind = event.get("type")
    if not isinstance(kind, str) or kind not in EVENT_TYPES:
        return "type 必须是 %s" % "/".join(sorted(EVENT_TYPES))
    if not _finite_number(event.get("ts")) or event["ts"] <= 0:
        return "ts 必须是正的有限数值"
    now = time.time() if now is None else now
    max_age = _nonnegative_env_float("FK_EVENT_MAX_AGE_SECONDS",
                                     EVENT_MAX_AGE_SECONDS)
    max_future = _nonnegative_env_float("FK_EVENT_MAX_FUTURE_SECONDS",
                                        EVENT_MAX_FUTURE_SECONDS)
    if source_kind == "legacy_client" and event["ts"] < now - max_age:
        return "ts 过旧(最多允许 %.0f 秒延迟)" % max_age
    if event["ts"] > now + max_future:
        return "ts 超前(最多允许 %.0f 秒时钟偏差)" % max_future
    amount = event.get("amount")
    if amount is not None and (not _finite_number(amount) or amount < 0):
        return "amount 必须是非负有限数值"
    if kind == "order" and amount is None:
        return "order 事件缺少 amount"
    for key in ("ip", "device_id"):
        value = event.get(key)
        if value is not None and (not isinstance(value, str) or len(value) > MAX_STRING_LEN):
            return "%s 必须是不超过 %d 字符的字符串" % (key, MAX_STRING_LEN)
    if event.get("ip"):
        try:
            ipaddress.ip_address(event["ip"])
        except ValueError:
            return "ip 格式无效"
    return ""


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        try:
            timeout = float(os.environ.get("FK_SERVE_REQUEST_TIMEOUT", REQUEST_TIMEOUT))
        except ValueError:
            timeout = REQUEST_TIMEOUT
        self.connection.settimeout(max(0.1, timeout))

    def _json(self, code: int, obj: dict) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):  # 访问日志走 stderr 会刷屏,静默
        pass

    def _require_auth(self) -> bool:
        self.auth_context = None
        if os.environ.get("FK_AUTH_CONFIG"):
            from agent.tenancy import authenticate
            try:
                self.auth_context = authenticate(self.headers.get("Authorization", ""))
                return True
            except PermissionError:
                self._json(401, {"error": "unauthorized"})
                return False
            except (ValueError, OSError):
                self._json(503, {"error": "auth_configuration_invalid"})
                return False
        if _valid_bearer(self.headers.get("Authorization", "")):
            return True
        self.send_response(401)
        self.send_header("WWW-Authenticate", "Bearer")
        body = b'{"error":"unauthorized"}'
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        return False

    def do_GET(self):
        if self.path == "/cases" or self.path.startswith("/evidence/"):
            if not self._require_auth():
                return
            if self.auth_context is None:
                self._json(403, {"error": "scoped_credential_required"})
                return
            try:
                if self.path == "/cases":
                    from agent.investigations import list_cases
                    self._json(200, {"cases": list_cases(self.auth_context)})
                else:
                    from agent.collector import get_observation
                    self._json(200, get_observation(self.path[len("/evidence/"):], self.auth_context))
            except PermissionError:
                self._json(403, {"error": "forbidden"})
            return
        if self.path == "/health":
            if os.environ.get("FK_AUTH_CONFIG"):
                self._json(200, {"ok": True})
                return
            from agent.engine import engine_status
            from agent.tools.policy import active_policy
            from agent.tools.readiness import _readiness
            self._json(200, {"ok": True, "policy_version": active_policy()["_version"],
                             "engine": engine_status()["mode"],
                             "readiness": _readiness()["overall"]})
        elif self.path == "/brief":
            if not self._require_auth():
                return
            from agent.tools.brief import daily_brief
            if self.auth_context is not None:
                from agent.tenancy import data_context
                try:
                    self.auth_context.require("brief.read")
                    with data_context(self.auth_context):
                        self._json(200, daily_brief())
                except PermissionError:
                    self._json(403, {"error": "forbidden"})
                return
            self._json(200, daily_brief())
        else:
            self._json(404, {"error": "unknown path,可用: GET /health /brief, POST /decide"})

    def do_POST(self):
        if self.path not in ("/decide", "/decisions", "/reports", "/attestation/challenge", "/attestation/enroll"):
            self._json(404, {"error": "unknown path"})
            return
        if not self._require_auth():
            return
        content_type = (self.headers.get("Content-Type", "").split(";", 1)[0]
                        .strip().lower())
        if content_type != "application/json":
            self._json(415, {"error": "Content-Type 必须是 application/json"})
            return
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            self._json(411, {"error": "缺少 Content-Length"})
            return
        try:
            length = int(raw_length)
        except ValueError:
            self._json(400, {"error": "body 必须是 JSON 事件"})
            return
        if length <= 0:
            self._json(400, {"error": "body 不能为空"})
            return
        if length > MAX_BODY:
            self._json(413, {"error": "body too large"})
            return
        try:
            raw = self.rfile.read(length)
            if len(raw) != length:
                self._json(400, {"error": "body 长度与 Content-Length 不符"})
                return
            def unique_object(pairs):
                obj = {}
                for key, value in pairs:
                    if key in obj:
                        raise ValueError("duplicate JSON key")
                    obj[key] = value
                return obj
            event = json.loads(raw, object_pairs_hook=unique_object)
        except socket.timeout:
            self._json(408, {"error": "request_timeout"})
            return
        except (ValueError, json.JSONDecodeError):
            self._json(400, {"error": "body 必须是 JSON 事件"})
            return
        if self.auth_context is not None:
            self._scoped_post(event, raw)
            return
        if self.path != "/decide":
            self._json(403, {"error": "scoped_credential_required"})
            return
        received_at = time.time()
        # Source trust is bound to this authenticated service deployment, never body fields.
        source_kind = os.environ.get("FK_SERVE_SOURCE_KIND", "legacy_client")
        invalid = _validate_event(event, now=received_at, source_kind=source_kind)
        if invalid:
            self._json(400, {"error": invalid})
            return
        operator, operator_error = _signed_operator(self.headers, "POST", self.path)
        if operator_error:
            self._json(401, {"error": operator_error})
            return
        try:
            self._json(200, _decide(event, operator=operator,
                                    received_at=received_at, source_kind=source_kind))
        except Exception as exc:
            from agent.tools.idemp_store import IdempotencyConflict
            if isinstance(exc, IdempotencyConflict):
                self._json(409, {"error": str(exc)})
                return
            self._json(500, {"error": "internal_error"})

    def _scoped_post(self, event, raw):
        from agent.tenancy import data_context
        from agent.tools.idemp_store import IdempotencyConflict
        ctx = self.auth_context
        try:
            with data_context(ctx):
                if self.path == "/reports":
                    from agent.collector import ingest
                    result = ingest(event, ctx, wire_bytes=raw, remote_ip=self.client_address[0])
                elif self.path == "/attestation/challenge":
                    from agent.collector import issue_challenge
                    if not isinstance(event, dict) or set(event) - {"purpose"}:
                        raise ValueError("invalid challenge request")
                    result = issue_challenge(ctx, purpose=event.get("purpose", "assertion"))
                elif self.path == "/attestation/enroll":
                    from agent.collector import register_attestation
                    result = register_attestation(event, ctx)
                else:
                    ctx.require("decisions.write")
                    if self.path == "/decisions":
                        from agent.contracts.business_contract import decision_event
                        event = decision_event(event)
                    error = _validate_event(event, now=time.time(), source_kind=ctx.source_kind)
                    if error:
                        raise ValueError(error)
                    from agent.collector import enrich_business_event
                    result = _decide(event, operator=ctx.principal, received_at=time.time(),
                                     scope=(ctx.tenant, ctx.app), source_kind=ctx.source_kind,
                                     prepare=lambda value, db: enrich_business_event(value, ctx, connection=db))
                    from agent.investigations import consume_decision_outbox
                    try:
                        consume_decision_outbox()
                        result["investigation_projection_status"] = "current"
                    except (OSError, ValueError, __import__("sqlite3").Error):
                        result["investigation_projection_status"] = "pending"
                self._json(200, result)
        except PermissionError:
            self._json(403, {"error": "forbidden"})
        except IdempotencyConflict as exc:
            self._json(409, {"error": str(exc)})
        except (ValueError, TypeError, KeyError) as exc:
            self._json(400, {"error": "invalid_request", "detail": str(exc)})
        except Exception:
            self._json(500, {"error": "internal_error"})


def main() -> None:
    ap = argparse.ArgumentParser(description="风控在线决策服务(骨架)")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()
    token = _serve_token()
    if os.environ.get("FK_AUTH_CONFIG"):
        from agent.tenancy import registry
        if not registry():
            raise SystemExit("拒绝启动:认证配置为空")
    elif len(token) < 16:
        raise SystemExit("拒绝启动:请设置至少 16 字符的 FK_SERVE_TOKEN")
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print("决策服务就绪 http://127.0.0.1:%d  (POST /decide, GET /health /brief)" % args.port)
    srv.serve_forever()


if __name__ == "__main__":
    main()
