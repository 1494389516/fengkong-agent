#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在线决策服务(骨架):把规则引擎包成 HTTP 端点,是"接真实流量"的最小形态。

端点:
  POST /decide   body 为事件 JSON(字段同 rule_eval 的 event),返回处置决策。
                 线上口径固定 use_current_policy=True(线上永远用当前策略;
                 回放历史策略是审计场景,不该出现在决策路径)。
                 每个决策追加写入 out/serve_decisions.jsonl —— 这就是
                 reconcile 对账语义里"生产决策日志"的雏形:本服务上生产后,
                 agent 的本地模拟就降级为镜像,靠这份日志对账。
  GET  /health   存活 + 当前策略版本(探针/发布检查用)。
  GET  /brief    值班日报(daily_brief),给内部看板/机器人拉取。

边界(诚实声明):
- /brief 与 /decide 强制 Bearer 认证(FK_SERVE_TOKEN);/health 保持匿名。
  网关如需注入 X-Operator,必须用 FK_OPERATOR_HMAC_SECRET 签名,
  未签名或过期的身份头会被拒绝,不作为审计事实。
- 幂等:必填 event_id 的哈希作唯一键，分片 flock 跨线程/进程合并；
  同 event_id 换请求体返回 409。记录有 TTL/容量上限，重放不写血缘/日志。
- 数据仍是 JSON 文件 + mtime 缓存。写路径(审批/申诉)仍走 CLI。

用法:python3 serve.py [--port 8080] ;FK_DATASET/FK_DATA_DIR 照常生效。
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
        "agent_cannot_override", "decision_combine")}
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
    write_lineage(logged_event, decision, approver=operator or "serve")
    append_jsonl(_log_path(), decision)
    return _public_view(decision, False)


def _decide(event: dict, operator: str = "serve", received_at: float = None) -> dict:
    from agent.tools.idemp_store import claim, complete, event_key, lookup, ttl_seconds
    from agent.tools.lineage import event_fingerprint
    key = event_key(event["event_id"])
    input_fp = event_fingerprint(event)
    with _mu:
        cached = _idemp.get(key)
        if cached is not None:
            if time.time() - cached["completed_at"] > ttl_seconds():
                _idemp.pop(key, None)
                cached = None
        if cached is not None:
            if cached["input_fingerprint"] != input_fp:
                from agent.tools.idemp_store import IdempotencyConflict
                raise IdempotencyConflict("event_id 已用于不同请求体")
            _idemp.move_to_end(key)
            return _replay(cached["public"])
    # 同键的跨线程/跨进程请求在计算全周期内串行。flock 由内核
    # 在进程崩溃时释放,比“等 15s 后直接重算”的租约更可靠。
    with claim(key):
        public = lookup(key, input_fp)
        if public is not None:
            _remember(key, input_fp, public)
            return _replay(public)
        evaluation_event = dict(event)
        if received_at is not None:
            evaluation_event["_source_ts"] = event["ts"]
            evaluation_event["ts"] = received_at
        public = _compute(evaluation_event, operator)
        complete(key, public, input_fp)
        _remember(key, input_fp, public)
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
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and math.isfinite(float(value)))


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


def _validate_event(event, now: float = None):
    if not isinstance(event, dict):
        return "body 必须是 JSON object"
    shape_error = _validate_json_value(event)
    if shape_error:
        return shape_error
    for key, limit in (("event_id", MAX_EVENT_ID_LEN), ("uid", MAX_UID_LEN)):
        value = event.get(key)
        if not isinstance(value, str) or not value.strip() or len(value) > limit:
            return "%s 必须是 1~%d 字符串" % (key, limit)
    kind = event.get("type")
    if kind not in EVENT_TYPES:
        return "type 必须是 %s" % "/".join(sorted(EVENT_TYPES))
    if not _finite_number(event.get("ts")) or event["ts"] <= 0:
        return "ts 必须是正的有限数值"
    now = time.time() if now is None else now
    max_age = _nonnegative_env_float("FK_EVENT_MAX_AGE_SECONDS",
                                     EVENT_MAX_AGE_SECONDS)
    max_future = _nonnegative_env_float("FK_EVENT_MAX_FUTURE_SECONDS",
                                        EVENT_MAX_FUTURE_SECONDS)
    if event["ts"] < now - max_age:
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
        if self.path == "/health":
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
            self._json(200, daily_brief())
        else:
            self._json(404, {"error": "unknown path,可用: GET /health /brief, POST /decide"})

    def do_POST(self):
        if self.path != "/decide":
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
            event = json.loads(raw)
        except socket.timeout:
            self._json(408, {"error": "request_timeout"})
            return
        except (ValueError, json.JSONDecodeError):
            self._json(400, {"error": "body 必须是 JSON 事件"})
            return
        received_at = time.time()
        invalid = _validate_event(event, now=received_at)
        if invalid:
            self._json(400, {"error": invalid})
            return
        operator, operator_error = _signed_operator(self.headers, "POST", self.path)
        if operator_error:
            self._json(401, {"error": operator_error})
            return
        try:
            self._json(200, _decide(event, operator=operator,
                                    received_at=received_at))
        except Exception as exc:
            from agent.tools.idemp_store import IdempotencyConflict
            if isinstance(exc, IdempotencyConflict):
                self._json(409, {"error": str(exc)})
                return
            self._json(500, {"error": "internal_error"})


def main() -> None:
    ap = argparse.ArgumentParser(description="风控在线决策服务(骨架)")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()
    token = _serve_token()
    if len(token) < 16:
        raise SystemExit("拒绝启动:请设置至少 16 字符的 FK_SERVE_TOKEN")
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print("决策服务就绪 http://127.0.0.1:%d  (POST /decide, GET /health /brief)" % args.port)
    srv.serve_forever()


if __name__ == "__main__":
    main()
