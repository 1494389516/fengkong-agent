#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""token 成本测量:工具 schema 总量 + 每个工具典型调用的结果大小。

为什么要单独量:① 只度量"已经花掉"的 token,这里量的是"结构性成本"——
schema 和 system prompt 每次请求都随行(缓存前缀可吸收,但决定了 miss 时的
底价),工具结果则逐轮进入历史且无法缓存(④ 只裁旧轮)。任何一个工具的
典型返回过大,都是复利式的上下文负担;eval 据此设了硬预算(结构性上限 +
单工具结果上限),超了直接红。

用法:python3 eval/measure_costs.py [--dataset sample|gen]
est tokens 用 chars/2(与 core.py ⑥ 同口径,中文偏保守)。
"""
import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def structural_sizes():
    """schema / system prompt 的字符量(数据集无关)。"""
    from agent import tools
    schemas_json = json.dumps(tools.schemas(), ensure_ascii=False)
    system_md = (ROOT / "agent" / "prompts" / "system.md").read_text(encoding="utf-8")
    return {"tool_count": len(tools.schemas()),
            "schemas_chars": len(schemas_json),
            "system_chars": len(system_md)}


def tool_result_sizes():
    """每个工具一次典型调用经 dispatch(含 ② 限幅)后的结果字符量。
    热点账号按当前数据集自动选(事件最多者 / 有属实举报者)。"""
    from agent import tools
    from agent.tools.datasource import load_events, load_reports

    events = load_events()
    counts = {}
    for e in events:
        counts[e["uid"]] = counts.get(e["uid"], 0) + 1
    uid_hot = max(counts, key=counts.get)
    verified = [r["reported_uid"] for r in load_reports() if r.get("status") == "verified"]
    uid_victim = verified[0] if verified else uid_hot

    calls = [
        ("blacklist_query", {"dimension": "uid", "value": uid_victim}),
        ("ip_intel", {"ip": "203.0.113.66"}),
        ("report_query", {"uid": uid_victim}),
        ("feature_stats", {"uid": uid_hot}),
        ("rule_eval", {"event": {"uid": uid_hot, "type": "coupon_claim"}}),
        ("account_monitor", {"uid": uid_hot}),
        ("policy_history", {}),
        ("consistency_check", {}),
        ("graph_relations", {}),
        ("scan_all", {}),
        ("account_profile", {"uid": uid_victim}),
        ("rule_backtest", {}),
        ("shadow_backtest", {"overrides": {"r002_min_events": 99}}),
        ("threshold_calibrate", {}),
        ("feature_drift", {}),
        ("rule_drift", {}),
        ("feature_risk", {}),
        ("adversary_watch", {}),
        ("rule_draft_test", {"conditions": [
            {"feature": "coupon_claims", "op": ">=", "value": 3}]}),
        ("appeal_review", {}),
        ("daily_brief", {}),
        ("chart_drift_dashboard", {}),
        ("chart_account_timeline", {"uid": uid_hot}),
        ("chart_cohort_features", {}),
        ("chart_threshold_sweep", {"param": "r002_min_events"}),
        ("audit_query", {"kind": "blacklist_add"}),
        ("feature_catalog", {}),
        ("build_dataset", {}),
        ("model_list", {}),
        ("model_register", {"name": "eval", "version": "0.0.1"}),
        ("model_eval", {"name": "n", "version": "v", "scores": {}}),
        ("model_promote", {"name": "n", "version": "v", "to": "shadow"}),
        ("model_rollback", {"name": "n", "version": "v", "reason": "x"}),
        ("model_status", {}),
        ("model_compare", {"challenger_name": "a", "challenger_version": "1",
                           "champion_name": "b", "champion_version": "1"}),
        ("strategy_register", {"strategy_name": "s", "version": "1"}),
        ("strategy_validate", {"strategy_name": "s", "version": "1"}),
        ("strategy_list", {}),
        ("strategy_diff", {"strategy_name": "s", "version_a": "1",
                           "version_b": "2"}),
        ("strategy_promote", {"strategy_name": "s", "version": "1",
                              "to": "validated"}),
        ("strategy_rollback", {"strategy_name": "s", "version": "1",
                               "reason": "x"}),
        ("strategy_replay", {"strategy_name": "s", "version": "1"}),
        ("strategy_shadow", {"strategy_name": "s", "version": "1"}),
        ("job_submit", {"type": "dataset_build"}),
        ("job_status", {"job_id": 1}),
        ("job_result", {"job_id": 1}),
        ("job_cancel", {"job_id": 1}),
        ("capability_registry", {}),
        ("feature_health_check", {}),
        ("feature_version", {}),
        ("feature_validate", {}),
        ("feature_diff", {"version_a": "x"}),
        ("decision_explain", {"event": {"uid": "u_1009"}}),
        ("decision_trace", {"event": {"uid": "u_1009"}}),
        ("incident_open", {"incident_type": "engine_mismatch", "summary": "x"}),
        ("incident_update", {"incident_id": 1, "note": "x"}),
        ("incident_resolve", {"incident_id": 1, "root_cause": "x",
                              "resolution": "y"}),
        ("incident_list", {}),
        ("data_health_check", {}),
        ("mismatch_queue", {}),
        ("mismatch_resolve", {"key": "nonexistent:0", "cause": "other"}),
        ("engine_status", {}),
    ]
    rows = []
    for name, call_args in calls:
        payload = json.dumps(tools.dispatch(name, dict(call_args)),
                             ensure_ascii=False, default=str)
        rows.append((name, len(payload)))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", choices=["sample", "gen"], default="sample")
    args = ap.parse_args()
    if args.dataset == "gen":
        os.environ["FK_DATASET"] = "gen"

    s = structural_sizes()
    print("== 结构性成本(每请求随行,prefix 缓存可吸收)==")
    print("  工具数: %d" % s["tool_count"])
    print("  schema 总量: %d chars ≈ %d tokens" % (s["schemas_chars"], s["schemas_chars"] // 2))
    print("  system prompt: %d chars ≈ %d tokens" % (s["system_chars"], s["system_chars"] // 2))

    rows = tool_result_sizes()
    print("\n== 工具结果大小(数据集: %s,经 dispatch 限幅后)==" % args.dataset)
    for name, size in sorted(rows, key=lambda r: -r[1]):
        print("  %-24s %7d chars ≈ %5d tokens" % (name, size, size // 2))
    total = sum(size for _, size in rows)
    print("  合计(全部各调一次): %d chars ≈ %d tokens" % (total, total // 2))


if __name__ == "__main__":
    main()
