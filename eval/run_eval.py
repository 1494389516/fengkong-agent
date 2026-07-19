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
sys.path.insert(0, str(Path(__file__).resolve().parent))  # 供导入 measure_costs

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
            cal = registry.dispatch("threshold_calibrate", {"fpr_budget": 0.01})
            realized = cal.get("realized_fpr_normal_wide")
            # token 成本预算:在同一份大样本上量每个工具的典型返回,超限即红。
            # 教训:rule_backtest 的 per_account 曾单次 18k+ chars,② 的 dict
            # 限幅与工具面瘦身都是这里钉住的。
            from measure_costs import tool_result_sizes
            sizes = dict(tool_result_sizes())
            biggest = max(sizes.items(), key=lambda kv: kv[1])
            failures = _report("数据生成 + 大样本回测(离线)", [
                ("生成器退出码 0", proc.returncode == 0),
                ("账号数 = 60(seed 7 确定性)", r["accounts_evaluated"] == 60),
                ("宽口径 recall >= 0.9", wide["recall"] >= 0.9),
                ("宽口径 precision >= 0.8", wide["precision"] >= 0.8),
                ("宽口径 f1 >= 0.85", wide["f1"] >= 0.85),
                ("严口径 precision >= 0.7", strict["precision"] >= 0.7),
                ("无生产日志时对账优雅降级",
                 registry.dispatch("consistency_check", {}).get("available") is False),
                ("校准产出建议阈值", bool(cal.get("suggestions"))),
                ("建议阈值实测误伤率 <= 5%", realized is not None and realized <= 0.05),
                ("无参照快照时不误报漂移", cal.get("drift_alarm") is False),
                ("单工具结果 <= 5000 chars(最大: %s %d)" % biggest, biggest[1] <= 5000),
                ("rule_backtest 已瘦身 <= 1500 chars(现 %d)" % sizes["rule_backtest"],
                 sizes["rule_backtest"] <= 1500),
            ])
            print("  宽口径 %s" % wide)
            print("  严口径 %s" % strict)
            print("  校准建议 %s(实测误伤率 %s)" % (cal.get("suggestions"), realized))
            return failures
        finally:
            os.environ.pop("FK_DATA_DIR", None)


def run_policy_layer() -> int:
    """离线:策略版本化 —— 同一账号的事件,结论随'当时生效的版本'切换;
    use_current_policy 则让历史事件吃到最新版(评估口径)。"""
    with tempfile.TemporaryDirectory() as td:
        for f in ("events_sample.json", "blacklist.json", "labels.json"):
            shutil.copy(ROOT / "data" / f, Path(td) / f)
        (Path(td) / "thresholds.json").write_text(json.dumps([
            {"version": 1, "effective_from": 0, "approved_by": "eval",
             "note": "基线", "values": {}},
            {"version": 2, "effective_from": 1784109631, "approved_by": "eval",
             "note": "大幅放宽 min_events", "values": {"r002_min_events": 99}},
        ]), encoding="utf-8")
        os.environ["FK_DATA_DIR"] = td
        try:
            early = {"uid": "u_1002", "ip": "203.0.113.10", "device_id": "dev_farm_x7",
                     "type": "coupon_claim", "ts": 1784109630}  # v1 生效期(min_events=10)
            late = dict(early, ts=1784109657)                   # v2 生效期(min_events=99)
            r_early = rule_eval(early)
            r_late = rule_eval(late)
            r_cur = rule_eval(early, use_current_policy=True)
            checks = [
                ("回放 v1 期事件:模式已成立应拦截",
                 r_early["action"] == "reject" and r_early["policy_version"] == 1),
                ("回放 v2 期事件:放宽后应放行",
                 r_late["action"] == "pass" and r_late["policy_version"] == 2),
                ("同一事件改用当前策略(v2):结论翻转",
                 r_cur["action"] == "pass" and r_cur["policy_version"] == 2),
            ]
        finally:
            os.environ.pop("FK_DATA_DIR", None)
    return _report("策略版本化(离线,临时目录)", checks)


def run_governance_layer() -> int:
    """离线:阈值提案 → 限速 → 审批落盘 → 漂移告警,全程临时目录。"""
    with tempfile.TemporaryDirectory() as td:
        for f in ("events_sample.json", "blacklist.json", "labels.json"):
            shutil.copy(ROOT / "data" / f, Path(td) / f)
        os.environ["FK_DATA_DIR"] = td
        try:
            r1 = registry.dispatch("threshold_propose",
                                   {"values": {"r002_min_events": 12}, "reason": "eval:测试"})
            r_limit = registry.dispatch("threshold_propose",
                                        {"values": {"r002_max_gap_seconds": 300}, "reason": "eval:大改"})
            actions.decide(r1.get("action_id", -1), approve=True)
            from agent.tools.policy import active_policy
            pol = active_policy()
            hist = registry.dispatch("policy_history", {})
            # 把已落盘版本的基线快照改成离谱值,漂移告警必须响
            tpath = Path(td) / "thresholds.json"
            versions = json.loads(tpath.read_text(encoding="utf-8"))
            versions[-1]["baseline_snapshot"] = {"event_count": {"p99": 1}}
            tpath.write_text(json.dumps(versions), encoding="utf-8")
            cal = registry.dispatch("threshold_calibrate", {})
            checks = [
                ("提案进入待审批", r1.get("status") == "pending_confirmation"),
                ("超幅提案被限速拒绝", r_limit.get("status") == "rejected_rate_limit"),
                ("批准后新版本生效", pol["r002_min_events"] == 12 and pol["_version"] == 1),
                ("版本历史可审计", len(hist.get("versions", [])) == 1),
                ("基线漂移触发告警", cal.get("drift_alarm") is True),
            ]
        finally:
            os.environ.pop("FK_DATA_DIR", None)
    return _report("策略治理(离线,临时目录)", checks)


def run_shadow_layer() -> int:
    """离线:影子回测 + 覆盖原子性(防部分应用泄漏的回归守卫)。"""
    r = registry.dispatch("shadow_backtest", {"overrides": {"r002_min_events": 99}})
    after_shadow = backtest()["operating_points"]["flag=review+reject"]
    bad = registry.dispatch("rule_backtest", {"overrides": {"r002_min_events": 5, "bogus": 1}})
    after_bad = backtest()["operating_points"]["flag=review+reject"]
    return _report("影子回测与覆盖原子性(离线)", [
        ("影子:u_1002 在候选阈值下会被放过", "u_1002" in r.get("newly_passed", [])),
        ("影子:宽口径 F1 增量为负", r.get("delta", {}).get("wide_f1", 0) < 0),
        ("影子跑完当前策略无残留(F1 复原)", after_shadow["f1"] == 1.0),
        ("含非法键的覆盖整体拒绝(原子)", "error" in bad),
        ("拒绝后阈值无泄漏(F1 复原)", after_bad["f1"] == 1.0),
    ])


def run_baseline_layer() -> int:
    """离线:人群基线/百分位 + 自身基线信号 + 配置与 DEFAULTS 一致性。"""
    from agent.tools.featurelib import percentile_rank, population_baseline
    from agent.tools.policy import DEFAULTS
    base = population_baseline()
    pr_gap = percentile_rank("min_gap_seconds", 3)
    pr_cnt = percentile_rank("event_count", 20)
    # 自身基线:临时数据集造一个"老账号突换设备 + 金额突增"的盗号形态
    with tempfile.TemporaryDirectory() as td:
        t0 = 1784000000
        evs = [{"uid": "t_1", "ip": "10.0.0.1", "device_id": "dev_A",
                "type": "order" if i % 2 else "login", "ts": t0 + i * 40000,
                **({"amount": 50.0} if i % 2 else {})} for i in range(6)]
        evs += [
            {"uid": "t_1", "ip": "10.0.0.2", "device_id": "dev_B", "type": "login",
             "ts": t0 + 300000},
            {"uid": "t_1", "ip": "10.0.0.2", "device_id": "dev_B", "type": "order",
             "ts": t0 + 300600, "amount": 900.0},
        ]
        (Path(td) / "events_sample.json").write_text(json.dumps(evs), encoding="utf-8")
        (Path(td) / "blacklist.json").write_text("[]", encoding="utf-8")
        os.environ["FK_DATA_DIR"] = td
        try:
            m = account_monitor("t_1")
        finally:
            os.environ.pop("FK_DATA_DIR", None)
    v1 = json.loads((ROOT / "data" / "thresholds.json").read_text(encoding="utf-8"))[0]["values"]
    return _report("基线与百分位(离线)", [
        ("人群基线覆盖关键特征", "min_gap_seconds" in base and base["event_count"]["n"] == 6),
        ("u_1002 间隔百分位极低(比几乎所有人快)", pr_gap is not None and pr_gap <= 0.2),
        ("u_1002 事件数百分位最高", pr_cnt == 1.0),
        ("自身基线:突换设备信号", "self_new_device" in m.get("signal_types", [])),
        ("自身基线:金额突增信号", "self_amount_spike" in m.get("signal_types", [])),
        ("thresholds.json v1 与 policy.DEFAULTS 一致", v1 == dict(DEFAULTS)),
    ])


def run_intel_layer() -> int:
    """离线:IP 情报与举报查询。"""
    i1 = registry.dispatch("ip_intel", {"ip": "203.0.113.66"})
    i2 = registry.dispatch("ip_intel", {"ip": "10.222.1.1"})
    r9 = registry.dispatch("report_query", {"uid": "u_1009"})
    r1 = registry.dispatch("report_query", {"uid": "u_1001"})
    return _report("IP 情报与举报(离线)", [
        ("机房段识别为 idc/high", i1.get("type") == "idc" and i1.get("risk") == "high"),
        ("未知段优雅降级", i2.get("type") == "unknown"),
        ("u_1009 有属实举报", r9.get("verified_count") == 1),
        ("u_1001 仅不实举报(不作处置依据)",
         r1.get("count") == 1 and r1.get("verified_count") == 0),
    ])


def run_profile_layer() -> int:
    """离线:账号档案 —— 主档/账龄错配/价值分档/注册环境联查/关联汇总。"""
    from agent.tools.profile import account_profile
    p9 = account_profile("u_1009")   # 老号高价值被盗形态
    p2 = account_profile("u_1002")   # 新号刷券形态
    p3 = account_profile("u_1003")   # 灰名单设备批量注册形态
    px = account_profile("u_9999")   # 无主档无事件,须优雅降级
    return _report("账号档案(离线)", [
        ("u_1009:老号高价值,误伤代价 high",
         p9["found_account"] and p9["age_days"] > 300 and p9["value"]["tier"] == "high"),
        ("u_1009:档案含地理跳变 + 机房 IP 证据",
         "geo_jump" in p9["monitor"]["signal_types"] and p9["ip_types"].get("idc", 0) > 0),
        ("u_1009:属实举报进入档案",
         p9["reports_against"]["verified"] >= 1),
        ("u_1002:新号(账龄 < 1 天)且判定 reject",
         p2["age_days"] < 1 and p2["current_verdict"]["predicted"] == "reject"),
        ("u_1003:注册设备命中灰名单",
         any("gray" in f for f in p3.get("registration_flags", []))),
        ("注册风险分随主档进入档案(u_1002 高分 / u_1009 注册时干净)",
         p2["account"].get("register_risk_score", 0) >= 70
         and p9["account"].get("register_risk_score", 99) <= 20
         and p2["account"].get("register_os") == "安卓"),
        ("u_1003:关联分量含团伙三账号",
         (p3.get("relations") or {}).get("accounts") == ["u_1003", "u_1004", "u_1005"]),
        ("无主档账号优雅降级",
         px["found_account"] is False and px["found_events"] is False),
    ])


def run_reconcile_layer() -> int:
    """离线:模拟一致性对账 —— 埋设的生产漂移必须被抓出,一致部分不得误报,
    失信标记必须自动挂到模拟类工具的返回上。"""
    r = registry.dispatch("consistency_check", {})
    got = {(m["uid"], m["ts"]) for m in r.get("mismatches", [])}
    planted = {("u_1001", 1784099100), ("u_1002", 1784109633), ("u_1003", 1784110800)}
    bt = registry.dispatch("rule_backtest", {})
    sim = bt.get("sim_consistency", {})
    return _report("模拟一致性对账(离线)", [
        ("对账覆盖全部日志与事件", r.get("compared") == 44 and r.get("orphan_decisions") == 0
         and r.get("uncovered_events") == 0),
        ("三条埋设的生产漂移全部抓出", planted <= got),
        ("一致部分无误报", got == planted),
        ("不一致率超线触发失信", r.get("trusted") is False and bool(r.get("warning"))),
        ("回测结果自动携带失信标记", sim.get("trusted") is False and bool(sim.get("warning"))),
    ])


def run_cost_layer() -> int:
    """离线:结构性 token 成本预算 —— schema 与 system prompt 每请求随行,
    缓存命中可吸收,但决定了 miss 时的底价;失控即工具设计出了问题。"""
    from measure_costs import structural_sizes
    s = structural_sizes()
    return _report("结构性成本预算(离线)", [
        ("工具 schema 总量 <= 12000 chars(现 %d,%d 个工具)"
         % (s["schemas_chars"], s["tool_count"]), s["schemas_chars"] <= 12000),
        ("system prompt <= 3000 chars(现 %d)" % s["system_chars"],
         s["system_chars"] <= 3000),
    ])


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
    """第 2+3 层的断言,返回问题列表(空 = 通过)。
    tool_calls 是 [(name, args_json)],除了'调没调对工具',还查'调得省不省':
    入口工具(聚合入口 vs 拆成多次单项)、调用次数上限、完全重复的调用。"""
    problems = []
    names = [n for n, _ in tool_calls]
    # 轨迹:先取证再下结论 —— 必须调过期望工具之一
    want = c.get("expect_tools_any", [])
    if want and not set(want) & set(names):
        problems.append("未调用任何取证工具(期望之一 %s,实际 %s)" % (want, names or "无"))
    # 轨迹效率:入口工具应是聚合入口(该一次 account_profile 的事拆成
    # 五次单项调用,答案对但成本翻倍 —— 18 工具时代的新失败模式)
    first = c.get("expect_first_tool_any", [])
    if first and names and names[0] not in first:
        problems.append("入口工具不经济:首调 %s(期望之一 %s)" % (names[0], first))
    cap = c.get("max_tool_calls")
    if cap and len(tool_calls) > cap:
        problems.append("工具调用 %d 次超上限 %d(疑似低效轨迹)" % (len(tool_calls), cap))
    dup = len(tool_calls) - len(set(tool_calls))
    if dup:
        problems.append("存在 %d 次完全重复的工具调用(同名同参,纯浪费)" % dup)
    # 回答:处置结论关键词
    ans = answer.lower()
    any_kw = c.get("expect_answer_any", [])
    if any_kw and not any(k.lower() in ans for k in any_kw):
        problems.append("回答缺少期望结论关键词(任一):%s" % any_kw)
    for k in c.get("expect_answer_all", []):
        if k.lower() not in ans:
            problems.append("回答缺少必含关键词:%s" % k)
    # 禁用表述:两阶段审批下,agent 把"已提交"说成"已生效"是权限越界话术,直接判负
    for k in c.get("forbid_answer_any", []):
        if k.lower() in ans:
            problems.append("回答包含禁用表述:%s" % k)
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
            answer = agent.ask(
                c["question"],
                on_tool=lambda n, a: tool_calls.append((n, json.dumps(a, sort_keys=True, ensure_ascii=False))))
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
        print("         工具 %d 次:%s | API %d 次 | token 总 %d(prompt %d / completion %d)| 缓存命中率 %.0f%%" % (
            len(tool_calls), ",".join(n for n, _ in tool_calls) or "无",
            used["api_calls"], used["total"],
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
    failures += run_policy_layer()
    failures += run_governance_layer()
    failures += run_shadow_layer()
    failures += run_baseline_layer()
    failures += run_intel_layer()
    failures += run_profile_layer()
    failures += run_reconcile_layer()
    failures += run_gen_layer()
    failures += run_cost_layer()
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
