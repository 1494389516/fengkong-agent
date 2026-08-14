#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""标注数据质量抽检:标签规范性 + 覆盖率 + 规则-标签冲突清单。

标签是回测/评估的地基,坏标签比没标签更危险(带毒训练材料)。三个检查:
  1. 规范性:labels.json 每条必须是 {label: fraud|normal},违者是硬错误;
  2. 覆盖率:events 里出现但未标注的 uid 清单(即回测 coverage 口径,
     未标注 ≠ normal,是"还不知道");
  3. 冲突清单:label=normal 但规则判定命中(疑似漏标)/ label=fraud 但判定
     pass(疑似漏拦漏标)——**只生成清单交人复核,绝不自动改标签**:
     改标签必须走标注 SOP(见 data/labeling_sop.md),误伤核实自动修正
     标签的路径已有(feedback.apply_appeal_decision)。

用法:
  python3 eval/label_quality.py            # FK_DATA_DIR / FK_DATASET 照常生效
  退出码:0 = 无硬错误(冲突清单只作警告输出);1 = 存在枚举违规。
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

VALID_LABELS = ("fraud", "normal")


def check_labels() -> dict:
    from agent.tools.backtest import account_verdicts
    from agent.tools.datasource import load_events, load_labels

    labels = load_labels()
    events = load_events()
    uids = {e["uid"] for e in events}
    violations = [u for u, v in labels.items()
                  if not isinstance(v, dict)
                  or v.get("label") not in VALID_LABELS]
    unlabeled = sorted(uids - set(labels))
    conflicts = []
    if labels:
        verdicts = account_verdicts(labels.keys(), events)
        for u, v in verdicts.items():
            pred = v.get("predicted", "pass")
            lab = labels[u]["label"]
            if lab == "normal" and pred != "pass":
                conflicts.append({"uid": u, "type": "label_normal_but_flagged",
                                  "predicted": pred,
                                  "rules": sorted(v.get("rules", []))})
            elif lab == "fraud" and pred == "pass":
                conflicts.append({"uid": u, "type": "label_fraud_but_passed",
                                  "predicted": pred,
                                  "rules": sorted(v.get("rules", []))})
    return {
        "labels": len(labels),
        "events_uids": len(uids),
        "violations": violations,
        "unlabeled": unlabeled,
        "conflicts": conflicts,
        "ok": not violations,
    }


def main() -> int:
    r = check_labels()
    print("标注总数: %d | 事件出现 uid 数: %d" % (r["labels"], r["events_uids"]))
    if r["violations"]:
        print("❌ 枚举违规(硬错误): %s" % r["violations"])
        return 1
    print("✅ 枚举规范: 全部为 fraud/normal")
    if r["unlabeled"]:
        print("⚠ 未标注 uid(%d 个,回测 coverage < 1): %s" % (
            len(r["unlabeled"]), r["unlabeled"][:20]))
    if r["conflicts"]:
        print("⚠ 规则-标签冲突清单(交人复核,不自动改):")
        for c in r["conflicts"]:
            print("   - %s %s predicted=%s rules=%s" % (
                c["uid"], c["type"], c["predicted"], c["rules"]))
    else:
        print("✅ 规则-标签无冲突")
    return 0


if __name__ == "__main__":
    sys.exit(main())
