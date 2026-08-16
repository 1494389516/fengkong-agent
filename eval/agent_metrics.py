#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""agent 运行指标聚合:读 out/agent_runs.jsonl,回答"agent 自己跑得怎么样"。

监控体系的空白面:drift/adversary 监控的是风控特征与规则,没有任何观测
回答 agent 本体 —— 每案例成本、缓存命中率、工具轮数、兜底触发率、工具
使用分布。本脚本把 FK_AGENT_RUN_LOG=1 落下的运行日志聚合为基础观测面,
是 agent 上线后的第一块自监控仪表。

用法:
  python3 eval/agent_metrics.py [path]    # 默认 out/agent_runs.jsonl
退出码:日志缺失返回 1(提示先开 FK_AGENT_RUN_LOG)。
纯 stdlib,可进 CI(结构性成本预算的运行时侧)。
"""
import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List

TOKEN_KEYS = ("prompt", "completion", "cache_hit", "cache_miss")


def _percentiles(vals: List[float]) -> Dict[str, float]:
    """p50/p95/p99/avg/max。空序列返回全 0(诚实:没数据就不是 0 以上的数)。"""
    if not vals:
        return {"p50": 0.0, "p95": 0.0, "p99": 0.0, "avg": 0.0, "max": 0.0,
                "n": 0}
    ordered = sorted(vals)
    n = len(ordered)

    def q(pct):
        idx = min(n - 1, int(pct * n))
        return round(ordered[idx], 1)

    return {"p50": q(0.50), "p95": q(0.95), "p99": q(0.99),
            "avg": round(sum(ordered) / n, 1), "max": round(ordered[-1], 1),
            "n": n}


def aggregate(path: Path, budgets: Dict[str, float] = None) -> dict:
    """聚合运行日志为指标 dict。损坏行跳过。
    budgets: {per_case_token_budget, per_case_latency_ms} —— 超限记为
    budget violation(阻断语义:CLI 退出码 2,CI 门禁据此拦截)。"""
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    n = len(records)
    tokens = Counter()
    rounds = []
    tools = Counter()
    compactions = 0
    lat_total, lat_llm, lat_tool = [], [], []
    tool_lat: Counter = Counter()
    for r in records:
        t = r.get("tokens") or {}
        for k in TOKEN_KEYS:
            tokens[k] += t.get(k, 0)
        rounds.append(int(r.get("tool_rounds") or r.get("api_calls") or 0))
        tools.update(r.get("tools_used") or [])
        if r.get("budget_compacted"):
            compactions += 1
        lat = r.get("latency_ms") or {}
        lat_total.append(float(lat.get("total_ms", 0.0)))
        lat_llm.append(float(lat.get("llm_ms", 0.0)))
        lat_tool.append(float(lat.get("tool_ms", 0.0)))
        for name, ms in r.get("tool_latency_ms") or []:
            tool_lat[name] += float(ms)
    hit, miss = tokens["cache_hit"], tokens["cache_miss"]
    budgets = budgets or {}
    tok_budget = budgets.get("per_case_token_budget", 60000)
    lat_budget = budgets.get("per_case_latency_ms", 120000)
    violations = []
    case_totals = []
    for r in records:
        t = r.get("tokens") or {}
        # prompt 已含 cache_hit+cache_miss,不能再把四键相加,否则均 token 虚高约一倍。
        case_tokens = int(t.get("prompt") or 0) + int(t.get("completion") or 0)
        case_totals.append(case_tokens)
        if case_tokens > tok_budget:
            violations.append({"case": r.get("ts"), "kind": "token_budget",
                               "value": case_tokens, "budget": tok_budget})
        case_lat = float((r.get("latency_ms") or {}).get("total_ms", 0.0))
        if case_lat > lat_budget:
            violations.append({"case": r.get("ts"), "kind": "latency_budget",
                               "value": case_lat, "budget": lat_budget})
    return {
        "cases": n,
        "api_calls": sum(int(r.get("api_calls") or 0) for r in records),
        "tokens": dict(tokens),
        "cache_hit_rate": round(hit / (hit + miss), 4) if (hit + miss) else 0.0,
        "avg_tokens_per_case": round(sum(case_totals) / n, 1) if n else 0.0,
        "avg_tool_rounds": round(sum(rounds) / n, 2) if n else 0.0,
        "max_tool_rounds": max(rounds, default=0),
        "budget_compactions": compactions,
        "top_tools": tools.most_common(10),
        "latency_ms": {"total": _percentiles(lat_total),
                       "llm": _percentiles(lat_llm),
                       "tool": _percentiles(lat_tool)},
        "tool_latency_ms": dict(tool_lat.most_common(10)),
        "budget_violations": violations,
        "budgets": {"per_case_token_budget": tok_budget,
                    "per_case_latency_ms": lat_budget},
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="agent 运行指标聚合")
    ap.add_argument("path", nargs="?", default="out/agent_runs.jsonl",
                    help="运行日志路径,默认 out/agent_runs.jsonl")
    args = ap.parse_args()
    p = Path(args.path)
    if not p.exists():
        print("无运行日志: %s(先 FK_AGENT_RUN_LOG=1 跑几轮对话)" % p)
        return 1
    rep = aggregate(p)
    t = rep["tokens"]
    lat = rep["latency_ms"]["total"]
    print("案例数: %d | API 调用: %d | 总 tokens: %d" % (
        rep["cases"], rep["api_calls"], sum(t.values())))
    print("缓存命中率: %.1f%% | 每案例均 tokens: %s | 工具轮数: 均 %s / 峰 %d" % (
        100 * rep["cache_hit_rate"], rep["avg_tokens_per_case"],
        rep["avg_tool_rounds"], rep["max_tool_rounds"]))
    print("延迟(ms): 总 p50/p95/p99 = %s/%s/%s,均 %s,峰 %s" % (
        lat["p50"], lat["p95"], lat["p99"], lat["avg"], lat["max"]))
    print("上下文兜底触发: %d 次 | 高频工具: %s" % (
        rep["budget_compactions"], rep["top_tools"] or "无"))
    if rep["budget_violations"]:
        print("❌ 预算违规 %d 条(阻断):" % len(rep["budget_violations"]))
        for v in rep["budget_violations"][:10]:
            print("   - %s %s=%.0f > 预算 %.0f" % (
                v["case"], v["kind"], v["value"], v["budget"]))
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
