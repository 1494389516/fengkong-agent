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

TOKEN_KEYS = ("prompt", "completion", "cache_hit", "cache_miss")


def aggregate(path: Path) -> dict:
    """聚合运行日志为指标 dict。损坏行跳过。"""
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
    for r in records:
        t = r.get("tokens") or {}
        for k in TOKEN_KEYS:
            tokens[k] += t.get(k, 0)
        rounds.append(int(r.get("tool_rounds") or r.get("api_calls") or 0))
        tools.update(r.get("tools_used") or [])
        if r.get("budget_compacted"):
            compactions += 1
    hit, miss = tokens["cache_hit"], tokens["cache_miss"]
    return {
        "cases": n,
        "api_calls": sum(int(r.get("api_calls") or 0) for r in records),
        "tokens": dict(tokens),
        "cache_hit_rate": round(hit / (hit + miss), 4) if (hit + miss) else 0.0,
        "avg_tokens_per_case": round(sum(tokens.values()) / n, 1) if n else 0.0,
        "avg_tool_rounds": round(sum(rounds) / n, 2) if n else 0.0,
        "max_tool_rounds": max(rounds, default=0),
        "budget_compactions": compactions,
        "top_tools": tools.most_common(10),
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
    print("案例数: %d | API 调用: %d | 总 tokens: %d" % (
        rep["cases"], rep["api_calls"], sum(t.values())))
    print("缓存命中率: %.1f%% | 每案例均 tokens: %s | 工具轮数: 均 %s / 峰 %d" % (
        100 * rep["cache_hit_rate"], rep["avg_tokens_per_case"],
        rep["avg_tool_rounds"], rep["max_tool_rounds"]))
    print("上下文兜底触发: %d 次" % rep["budget_compactions"])
    print("高频工具: %s" % (rep["top_tools"] or "无"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
