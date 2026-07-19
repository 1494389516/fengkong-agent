#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""复盘 → eval 误伤守卫用例草稿:把线上教训变成回归测试的半自动一步。

postmortems.jsonl 里的每条误伤复盘(申诉核实的 FP)对应一个"这类账号
不该被拦"的事实。本脚本读复盘,取该账号命中过规则的代表事件,生成
rule_cases 格式的守卫用例草稿(expect_action=pass)打到 stdout ——
研究员审阅、改名、贴进 eval/cases.json 的 rule_cases 后,同类误伤复发
时第 1 层评估直接红,不用等下一次申诉。

为什么是草稿不是自动写入:用例进 cases.json 等于定义"正确",这一步
必须过人 —— 复盘本身也可能错(申诉核实错了),自动化到底会把错误定型。

用法:python3 eval/postmortem_to_cases.py [--dataset gen]
"""
import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", choices=["sample", "gen"], default="sample")
    args = ap.parse_args()
    if args.dataset == "gen":
        os.environ["FK_DATASET"] = "gen"

    from agent.tools.datasource import load_events, postmortems_path

    p = postmortems_path()
    if not p.exists():
        print("无复盘记录(%s 不存在)" % p, file=sys.stderr)
        return 0
    events = load_events()
    drafts = []
    for line in p.read_text(encoding="utf-8").splitlines():
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("kind") != "false_positive_appeal":
            continue
        uid = rec.get("uid")
        mine = sorted((e for e in events if e["uid"] == uid), key=lambda e: e["ts"])
        if not mine:
            continue
        # 代表事件取末事件:账号模式最完整的时点,误伤通常发生在这里
        drafts.append({
            "name": "误伤守卫(复盘 appeal#%s):%s 不应被拦" % (rec.get("appeal_id"), uid),
            "event": mine[-1],
            "expect_action": "pass",
            "expect_rules": [],
            "_postmortem": {"rules_involved": rec.get("rules_involved", []),
                            "reason": rec.get("reason", "")},
        })
    if not drafts:
        print("复盘里没有误伤记录,无草稿可生成", file=sys.stderr)
        return 0
    print(json.dumps(drafts, ensure_ascii=False, indent=1))
    print("\n// 审阅后并入 eval/cases.json 的 rule_cases(删掉 _postmortem 注记)",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
