#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""评估 harness:三层评估 agent 效果,并把 token 成本一起测掉。

第 1 层 规则层(离线):对标注事件直接跑 rule_eval,比对期望处置与命中规则。
        零成本、确定性,改规则/阈值后必跑,防回归也防误伤(案例集里有守卫案例)。
第 2 层 轨迹层(需 DEEPSEEK_API_KEY):检查 agent 是否遵守"先取证再下结论"
        —— 每个案例必须调过期望工具之一,凭空下结论直接判负。
第 3 层 回答层(需 DEEPSEEK_API_KEY):golden case 关键词断言 + 每案例
        token / 缓存命中率报告,超预算判负。效果和成本共用同一个 harness,
        调 core.py 的 ④⑤ 上下文参数时能同时看到"省了多少"和"答案有没有变差"。

用法:
  python3 eval/run_eval.py            # 有 key 跑三层;没 key 自动只跑第 1 层
  python3 eval/run_eval.py --offline  # 强制只跑第 1 层
案例定义在 eval/cases.json。退出码:全过 0,有失败 1。
"""
import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.tools.backtest import backtest  # noqa: E402
from agent.tools.charts import (chart_account_timeline, chart_cohort_features,  # noqa: E402
                                chart_threshold_sweep)
from agent.tools.monitor import account_monitor  # noqa: E402
from agent.tools.rules import rule_eval  # noqa: E402


def load_cases():
    with open(Path(__file__).parent / "cases.json", encoding="utf-8") as f:
        return json.load(f)


def run_rule_layer(cases) -> int:
    """第 1 层:确定性规则回归,返回失败数。"""
    print("== 第 1 层 规则层(离线,%d 个案例)==" % len(cases))
    failures = 0
    for c in cases:
        r = rule_eval(c["event"])
        got_rules = sorted({h["rule_id"] for h in r["hits"]})
        ok = r["action"] == c["expect_action"] and got_rules == sorted(c["expect_rules"])
        if not ok:
            failures += 1
        print("  [%s] %s" % ("PASS" if ok else "FAIL", c["name"]))
        if not ok:
            print("         action=%s(期望 %s) rules=%s(期望 %s)" % (
                r["action"], c["expect_action"],
                ",".join(got_rules) or "-", ",".join(sorted(c["expect_rules"])) or "-"))
            for h in r["hits"]:
                print("         命中 %s[%s]: %s" % (h["rule_id"], h["action"], h["reason"]))
    return failures


def run_backtest_layer(checks) -> int:
    """离线:基线指标断言。数值漂了说明规则行为变了,即使方向是'变好'也要显式确认。"""
    print("\n== 指标回测(离线)==")
    failures = 0
    r = backtest()
    for point, expects in checks.items():
        if point.startswith("_"):
            continue
        got = r["operating_points"][point]
        for metric, want in expects.items():
            ok = abs(got[metric] - want) < 1e-6
            if not ok:
                failures += 1
            print("  [%s] %s %s=%.4f(期望 %.4f)" % (
                "PASS" if ok else "FAIL", point, metric, got[metric], want))
    if r["misclassified_at_review_point"]:
        print("  宽口径误判账号:%s" % r["misclassified_at_review_point"])
    return failures


def run_monitor_layer(cases) -> int:
    """离线:监控信号断言,含误伤守卫(正常账号必须零信号)。"""
    print("\n== 监控信号(离线,%d 个案例)==" % len(cases))
    failures = 0
    for c in cases:
        r = account_monitor(c["uid"])
        got = r.get("signal_types", [])
        problems = []
        want_any = c.get("expect_signal_any", [])
        if want_any and not set(want_any) & set(got):
            problems.append("缺少期望信号(任一):%s,实际 %s" % (want_any, got or "无"))
        if "expect_signal_count" in c and len(got) != c["expect_signal_count"]:
            problems.append("信号数 %d != 期望 %d,实际信号 %s" % (len(got), c["expect_signal_count"], got))
        if problems:
            failures += 1
        print("  [%s] %s(信号:%s)" % ("PASS" if not problems else "FAIL",
                                         c["name"], ",".join(got) or "无"))
        for p in problems:
            print("         问题:%s" % p)
    return failures


def run_chart_smoke() -> int:
    """离线:图表冒烟 —— 两类图各渲染一次,文件真实落盘即过。"""
    print("\n== 图表冒烟(离线)==")
    failures = 0
    for name, result in (
        ("账号时间线 u_1002", chart_account_timeline("u_1002")),
        ("阈值扫描 r002_min_events", chart_threshold_sweep("r002_min_events")),
        ("群体特征对比", chart_cohort_features()),
    ):
        path = result.get("chart_path", "")
        ok = bool(path) and (ROOT / path).exists()
        if not ok:
            failures += 1
        print("  [%s] %s -> %s" % ("PASS" if ok else "FAIL", name, path or result))
    return failures


def _check_agent_case(c, answer, tool_calls, used):
    """第 2+3 层的断言,返回问题列表(空 = 通过)。"""
    problems = []
    # 轨迹:先取证再下结论 —— 必须调过期望工具之一
    want = c.get("expect_tools_any", [])
    if want and not set(want) & set(tool_calls):
        problems.append("未调用任何取证工具(期望之一 %s,实际 %s)" % (want, tool_calls or "无"))
    # 回答:处置结论关键词
    ans = answer.lower()
    any_kw = c.get("expect_answer_any", [])
    if any_kw and not any(k.lower() in ans for k in any_kw):
        problems.append("回答缺少期望结论关键词(任一):%s" % any_kw)
    for k in c.get("expect_answer_all", []):
        if k.lower() not in ans:
            problems.append("回答缺少必含关键词:%s" % k)
    # 成本:token 预算(防上下文参数改坏后成本悄悄回归)
    budget = c.get("max_total_tokens")
    if budget and used["total"] > budget:
        problems.append("token 超预算:%d > %d" % (used["total"], budget))
    return problems


def run_agent_layers(cases) -> int:
    """第 2+3 层:轨迹 + 回答 + 成本。每案例 reset(即 ③ 案例隔离的正确用法),
    用 session_usage 前后差值得到单案例成本。返回失败数。"""
    from agent.core import Agent  # 延迟导入:离线模式不需要 openai / API key

    agent = Agent()
    print("\n== 第 2+3 层 轨迹/回答层(模型 %s,%d 个案例)==" % (agent.model, len(cases)))
    failures = 0
    for c in cases:
        agent.reset()  # ③ 每个案例干净上下文,互不串证据
        before = dict(agent.session_usage)
        tool_calls = []
        try:
            answer = agent.ask(c["question"], on_tool=lambda n, a: tool_calls.append(n))
        except Exception as e:  # noqa: BLE001 API 异常算该案例失败,不中断整场评估
            failures += 1
            print("  [FAIL] %s\n         调用异常:%s: %s" % (c["name"], type(e).__name__, e))
            continue
        used = {k: agent.session_usage[k] - before[k] for k in before}
        denom = used["cache_hit"] + used["cache_miss"]
        hit_rate = used["cache_hit"] / denom if denom else 0.0
        problems = _check_agent_case(c, answer, tool_calls, used)
        if problems:
            failures += 1
        print("  [%s] %s" % ("PASS" if not problems else "FAIL", c["name"]))
        print("         工具:%s | API %d 次 | token 总 %d(prompt %d / completion %d)| 缓存命中率 %.0f%%" % (
            ",".join(tool_calls) or "无", used["api_calls"], used["total"],
            used["prompt"], used["completion"], 100.0 * hit_rate))
        for p in problems:
            print("         问题:%s" % p)
    s = agent.session_usage
    print("  [合计] API %d 次 · token 总 %d · 整场缓存命中率 %.0f%%" % (
        s["api_calls"], s["total"], 100.0 * agent.cache_hit_rate()))
    return failures


def main() -> int:
    ap = argparse.ArgumentParser(description="风控 agent 三层评估")
    ap.add_argument("--offline", action="store_true", help="只跑第 1 层规则评估,不调 API")
    args = ap.parse_args()
    cases = load_cases()
    failures = run_rule_layer(cases["rule_cases"])
    failures += run_backtest_layer(cases["backtest_checks"])
    failures += run_monitor_layer(cases["monitor_cases"])
    failures += run_chart_smoke()
    if args.offline:
        pass
    elif not os.environ.get("DEEPSEEK_API_KEY"):
        print("\n(未设置 DEEPSEEK_API_KEY,跳过第 2+3 层 agent 评估)")
    else:
        failures += run_agent_layers(cases["agent_cases"])
    print("\n结果:%s" % ("全部通过" if failures == 0 else "%d 项失败" % failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
