#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""评估 harness:三层评估 agent 效果,并把 token 成本一起测掉。

第 1 层 规则层(离线):对标注事件直接跑 rule_eval,比对期望处置与命中规则。
        零成本、确定性,改规则/阈值后必跑,防回归也防误伤(案例集里有守卫案例)。
        同属离线的还有:指标回测基线、监控信号、全量巡检、关联图谱、
        处置写流程(临时目录)、数据生成器 + 大样本回测下限、图表冒烟。
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
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# 评估必须跑在确定性的手工样本上,清掉可能残留的数据集切换
os.environ.pop("FK_DATA_DIR", None)
os.environ.pop("FK_DATASET", None)

from agent import tools as registry  # noqa: E402
from agent.tools import actions  # noqa: E402
from agent.tools.backtest import backtest  # noqa: E402
from agent.tools.blacklist import blacklist_query  # noqa: E402
from agent.tools.charts import (chart_account_timeline, chart_cohort_features,  # noqa: E402
                                chart_threshold_sweep)
from agent.tools.graph import graph_relations  # noqa: E402
from agent.tools.monitor import account_monitor  # noqa: E402
from agent.tools.rules import rule_eval  # noqa: E402
from agent.tools.scan import scan_all  # noqa: E402


def _report(title: str, checks) -> int:
    """打印一组 (名称, 是否通过) 检查,返回失败数。"""
    print("\n== %s ==" % title)
    failures = 0
    for name, ok in checks:
        if not ok:
            failures += 1
        print("  [%s] %s" % ("PASS" if ok else "FAIL", name))
    return failures


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


def run_scan_layer() -> int:
    """离线:全量巡检结果与规则层口径一致。"""
    r = scan_all()
    reject = {x["uid"] for x in r["reject"]}
    review = {x["uid"] for x in r["review"]}
    return _report("全量巡检(离线)", [
        ("reject 组 = {u_1002, u_1009}", reject == {"u_1002", "u_1009"}),
        ("review 组 = 套现团伙三账号", review == {"u_1003", "u_1004", "u_1005"}),
        ("pass 计数 = 1(仅 u_1001)", r["pass_count"] == 1),
    ])


def run_graph_layer() -> int:
    """离线:关联图谱应恰好找出样本里的一个设备共用团伙。"""
    r = graph_relations()
    comp = r["components"][0] if r["components"] else {}
    return _report("关联图谱(离线)", [
        ("样本恰有 1 个多账号分量", r["component_count"] == 1),
        ("分量成员为套现团伙三账号", comp.get("accounts") == ["u_1003", "u_1004", "u_1005"]),
        ("共用设备为灰名单模拟器", "dev_emu_9f3a" in comp.get("devices", [])
         and any("gray" in h for h in comp.get("blacklist_hits", []))),
        ("图谱 PNG 落盘", bool(r["chart_path"]) and (ROOT / r["chart_path"]).exists()),
    ])


def run_actions_layer() -> int:
    """离线:处置写入的两阶段流程,在临时目录里走全程(不碰真实数据)。"""
    with tempfile.TemporaryDirectory() as td:
        shutil.copy(ROOT / "data" / "blacklist.json", Path(td) / "blacklist.json")
        os.environ["FK_DATA_DIR"] = td
        try:
            req = {"dimension": "uid", "value": "u_evil", "list": "black",
                   "reason": "eval:测试流程"}
            r1 = registry.dispatch("blacklist_add", dict(req))
            aid = r1.get("action_id", -1)
            r_dup = registry.dispatch("blacklist_add", dict(req))
            before = blacklist_query("uid", "u_evil")["hit"]
            actions.decide(aid, approve=True)
            after = blacklist_query("uid", "u_evil")["hit"]
            r_again = registry.dispatch("blacklist_add", dict(req))
            return _report("处置写流程(离线,临时目录)", [
                ("提交进入待审批", r1.get("status") == "pending_confirmation"),
                ("重复提交防重", r_dup.get("status") == "already_pending"),
                ("批准前名单未生效", before is False),
                ("批准后名单生效", after is True),
                ("已在名单的重复申请被拒", r_again.get("status") == "already_listed"),
                ("审计日志落盘", (Path(td) / "audit.jsonl").exists()),
            ])
        finally:
            os.environ.pop("FK_DATA_DIR", None)


def run_gen_layer() -> int:
    """离线:生成器产出小规模数据集,回测指标须过下限。
    下限故意留了余量(生成含随机性,虽然种子固定,但规则阈值调整后指标会漂),
    跌破下限说明规则对典型欺诈模式的覆盖坏了,而不只是数值抖动。"""
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "gen"
        proc = subprocess.run(
            [sys.executable, str(ROOT / "data" / "gen_sample.py"),
             "--normal", "40", "--bots", "4", "--rings", "3", "--stolen", "3",
             "--seed", "7", "--out", str(out)],
            capture_output=True, text=True)
        os.environ["FK_DATA_DIR"] = str(out)
        try:
            r = backtest()
            wide = r["operating_points"]["flag=review+reject"]
            strict = r["operating_points"]["flag=reject_only"]
            failures = _report("数据生成 + 大样本回测(离线)", [
                ("生成器退出码 0", proc.returncode == 0),
                ("账号数 = 60", r["accounts_evaluated"] == 60),
                ("宽口径 recall >= 0.9", wide["recall"] >= 0.9),
                ("宽口径 precision >= 0.8", wide["precision"] >= 0.8),
                ("宽口径 f1 >= 0.85", wide["f1"] >= 0.85),
                ("严口径 precision >= 0.7", strict["precision"] >= 0.7),
            ])
            print("  宽口径 %s" % wide)
            print("  严口径 %s" % strict)
            return failures
        finally:
            os.environ.pop("FK_DATA_DIR", None)


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
    failures += run_scan_layer()
    failures += run_graph_layer()
    failures += run_actions_layer()
    failures += run_gen_layer()
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
