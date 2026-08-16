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
- 纯 stdlib(ThreadingHTTPServer),无鉴权无限流 —— 只能内网使用;上公网
  前置网关做认证与限流(见 DEPLOY.md)。SSO 接缝:X-Operator 或 FK_OPERATOR
  写入血缘 approver,缺省 serve;网关应在前面鉴权再注入身份。
- 幂等:事件指纹唯一键落盘(decide_idemp.json)+ 进程内 in-flight 合并;
  同机多进程共享 data_dir 即共享幂等表。重放不写血缘/日志。
- 数据仍是 JSON 文件 + mtime 缓存。写路径(审批/申诉)仍走 CLI。

用法:python3 serve.py [--port 8080] ;FK_DATASET/FK_DATA_DIR 照常生效。
"""
import argparse
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LOG_PATH = ROOT / "out" / "serve_decisions.jsonl"
MAX_BODY = 64 * 1024
_mu = threading.Lock()
_idemp: dict = {}
_inflight: dict = {}


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
    from agent.tools.lineage import write_lineage
    from agent.tools.rules import rule_eval
    t0 = time.time()
    r = rule_eval(event, use_current_policy=True)
    decision = {
        "ts": time.time(),
        "event": event,
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
    write_lineage(event, decision, approver=operator or "serve")
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(decision, ensure_ascii=False) + "\n")
    return _public_view(decision, False)


def _decide(event: dict, operator: str = "serve") -> dict:
    from agent.tools.idemp_store import abort, begin, complete, lookup, wait_done
    from agent.tools.lineage import event_fingerprint
    fp = event_fingerprint(event)
    with _mu:
        cached = _idemp.get(fp)
        if cached is not None:
            return _replay(cached)
        ev = _inflight.get(fp)
        if ev is None:
            ev = threading.Event()
            _inflight[fp] = ev
            owner = True
        else:
            owner = False
    if not owner:
        ev.wait(timeout=30)
        with _mu:
            cached = _idemp.get(fp)
        if cached is not None:
            return _replay(cached)
        disk = lookup(fp)
        if disk is not None:
            return _replay(disk)
    try:
        state = begin(fp)
        if state == "hit":
            public = lookup(fp)
            if public is not None:
                with _mu:
                    _idemp[fp] = dict(public)
                return _replay(public)
        if state == "wait":
            public = wait_done(fp)
            if public is not None:
                with _mu:
                    _idemp[fp] = dict(public)
                return _replay(public)
        public = _compute(event, operator)
        complete(fp, public)
        with _mu:
            _idemp[fp] = dict(public)
        return public
    except Exception:
        abort(fp)
        raise
    finally:
        with _mu:
            held = _inflight.pop(fp, None)
            if held is not None:
                held.set()


class Handler(BaseHTTPRequestHandler):
    def _json(self, code: int, obj: dict) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):  # 访问日志走 stderr 会刷屏,静默
        pass

    def do_GET(self):
        if self.path == "/health":
            from agent.engine import engine_status
            from agent.tools.policy import active_policy
            from agent.tools.readiness import _readiness
            self._json(200, {"ok": True, "policy_version": active_policy()["_version"],
                             "engine": engine_status()["mode"],
                             "readiness": _readiness()["overall"]})
        elif self.path == "/brief":
            from agent.tools.brief import daily_brief
            self._json(200, daily_brief())
        else:
            self._json(404, {"error": "unknown path,可用: GET /health /brief, POST /decide"})

    def do_POST(self):
        if self.path != "/decide":
            self._json(404, {"error": "unknown path"})
            return
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            self._json(400, {"error": "body 必须是 JSON 事件"})
            return
        if length > MAX_BODY:
            self._json(413, {"error": "body too large"})
            return
        try:
            event = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError):
            self._json(400, {"error": "body 必须是 JSON 事件"})
            return
        if not isinstance(event, dict) or not event.get("uid"):
            self._json(400, {"error": "事件缺少 uid"})
            return
        operator = (self.headers.get("X-Operator")
                    or os.environ.get("FK_OPERATOR") or "serve")
        try:
            self._json(200, _decide(event, operator=operator))
        except Exception:  # noqa: BLE001 决策异常必须显式 500,细节不回给调用方
            self._json(500, {"error": "internal_error"})


def main() -> None:
    ap = argparse.ArgumentParser(description="风控在线决策服务(骨架)")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print("决策服务就绪 http://127.0.0.1:%d  (POST /decide, GET /health /brief)" % args.port)
    srv.serve_forever()


if __name__ == "__main__":
    main()
