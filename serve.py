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
  前置网关做认证与限流(见 DEPLOY.md)。
- 数据仍是 JSON 文件 + mtime 缓存:并发读安全(CPython 字典操作原子),
  写路径(审批/申诉)仍走 CLI 单进程 —— 服务只读策略与数据,不落处置。
- 单事件决策延迟 = 特征计算(账号事件索引缓存后为该账号事件量级),
  真实规模下特征须下推数仓预计算(featurelib 签名即接口契约)。

用法:python3 serve.py [--port 8080] ;FK_DATASET/FK_DATA_DIR 照常生效。
"""
import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LOG_PATH = ROOT / "out" / "serve_decisions.jsonl"
_log_lock = threading.Lock()


def _decide(event: dict) -> dict:
    from agent.tools.rules import rule_eval
    t0 = time.time()
    r = rule_eval(event, use_current_policy=True)
    decision = {
        "ts": time.time(),
        "event": event,
        "action": r["action"],
        "rules": sorted({h["rule_id"] for h in r["hits"]}),
        "policy_version": r["policy_version"],
        "latency_ms": round(1000 * (time.time() - t0), 1),
    }
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _log_lock:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(decision, ensure_ascii=False) + "\n")
    # 返回体不含 features_snapshot(那是调查素材,不是决策接口的一部分)
    return {k: decision[k] for k in ("action", "rules", "policy_version", "latency_ms")}


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
            self._json(200, {"ok": True, "policy_version": active_policy()["_version"],
                             "engine": engine_status()["mode"]})
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
            length = int(self.headers.get("Content-Length", 0))
            event = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError):
            self._json(400, {"error": "body 必须是 JSON 事件"})
            return
        if not isinstance(event, dict) or not event.get("uid"):
            self._json(400, {"error": "事件缺少 uid"})
            return
        try:
            self._json(200, _decide(event))
        except Exception as e:  # noqa: BLE001 决策异常必须显式 500,不能静默放行
            self._json(500, {"error": "%s: %s" % (type(e).__name__, e)})


def main() -> None:
    ap = argparse.ArgumentParser(description="风控在线决策服务(骨架)")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print("决策服务就绪 http://127.0.0.1:%d  (POST /decide, GET /health /brief)" % args.port)
    srv.serve_forever()


if __name__ == "__main__":
    main()
