#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""一日接数脚本:生成(或复用)大样本,跑健康/对账/回测/parity/门禁。

这是 DEPLOY.md 第一周清单在骨架里能自动跑完的那一段 —— 没有真实数仓时,
用 gen_sample 当"一天脱敏导出"的替身,把接数后第一道工序钉成命令,
而不是口头 checklist。换成真实目录:FK_DATA_DIR=/path python3 eval/day1.py --skip-gen

退出码:数据硬伤(data_health=fail)为 1;其余(含就绪 BLOCKED)为 0 ——
无 champion 在骨架上是预期,不能把"治理资产未登记"当成接数失败。
"""
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "eval"))

GEN_DIR = ROOT / "data" / "gen"
OUT = ROOT / "out" / "day1_report.md"
POLICY_FILES = ("thresholds.json", "appeals.json")


def _ensure_policy_files() -> None:
    GEN_DIR.mkdir(parents=True, exist_ok=True)
    for name in POLICY_FILES:
        src = ROOT / "data" / name
        dst = GEN_DIR / name
        if src.exists() and not dst.exists():
            shutil.copy(src, dst)


def _gen(force: bool) -> None:
    if GEN_DIR.exists() and (GEN_DIR / "events_sample.json").exists() and not force:
        print("复用已有生成集: %s" % GEN_DIR)
        _ensure_policy_files()
        return
    print("生成合成大样本 -> %s" % GEN_DIR)
    subprocess.check_call(
        [sys.executable, str(ROOT / "data" / "gen_sample.py"),
         "--out", str(GEN_DIR), "--seed", "42"],
        cwd=str(ROOT))
    _ensure_policy_files()


def _run_checks() -> dict:
    if not os.environ.get("FK_DATA_DIR"):
        os.environ["FK_DATASET"] = "gen"
    from agent.tools.backtest import backtest
    from agent.tools.feature_parity import feature_parity_check
    from agent.tools.health import data_health_check
    from agent.tools.feature_health import feature_health_check
    from agent.tools.readiness import _readiness
    from agent.tools.reconcile import consistency_check
    from label_quality import check_labels

    dh = data_health_check()
    fh = feature_health_check()
    lq = check_labels()
    parity = feature_parity_check()
    recon = consistency_check()
    bt = backtest()
    ready = _readiness()
    return {
        "data_health": dh,
        "feature_health": fh,
        "label_quality": lq,
        "feature_parity": parity,
        "consistency": recon,
        "backtest": bt,
        "readiness": ready,
    }


def _render(rep: dict) -> str:
    dh, fh, lq = rep["data_health"], rep["feature_health"], rep["label_quality"]
    parity, recon, bt = rep["feature_parity"], rep["consistency"], rep["backtest"]
    ready = rep["readiness"]
    wide = {}
    if isinstance(bt, dict):
        wide = (bt.get("operating_points") or {}).get("flag=review+reject") or {}
    lines = [
        "# 一日接数报告",
        "",
        "| 项 | 值 |",
        "|---|---|",
        "| 生成时间(UTC) | %s |" % datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"),
        "| 数据集 | FK_DATASET=gen (`data/gen/`) |",
        "| data_health | %s |" % dh.get("summary"),
        "| feature_health | %s |" % fh.get("summary"),
        "| label conflicts | %s |" % len(lq.get("conflicts") or []),
        "| feature_parity | %s / source=%s |" % (
            parity.get("verdict", "?"), parity.get("source", "?")),
        "| consistency | available=%s trusted=%s |" % (
            recon.get("available"), recon.get("trusted")),
        "| readiness | %s |" % ready.get("overall"),
        "",
        "## 回测(宽口径,生成集)",
        "",
        "```json",
        json.dumps({k: wide.get(k) for k in (
            "precision", "recall", "f1", "tp", "fp", "fn", "tn")
            if isinstance(wide, dict)}, ensure_ascii=False, indent=2),
        "```",
        "",
        "## 就绪分项",
        "",
        "| 检查 | 级别 | 详情 |",
        "|---|---|---|",
    ]
    for name, item in (ready.get("checks") or {}).items():
        lines.append("| %s | %s | %s |" % (
            name, item.get("level"), item.get("detail")))
    lines += [
        "",
        "## 说明",
        "",
        "- 生成集没有生产决策日志:consistency 应为未对账/不可用,这是诚实降级;",
        "- 无 champion / 无 active strategy:readiness=BLOCKED 是骨架预期,不是接数失败;",
        "- feature_parity 未注入在线实现时只能声明同源一致,不能声称线上已验证;",
        "- 换成真实导出后用 `FK_DATA_DIR=/path python3 eval/day1.py --skip-gen`。",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="一日接数:生成集健康/回测/对账/门禁")
    ap.add_argument("--force-gen", action="store_true", help="强制重新生成 data/gen/")
    ap.add_argument("--skip-gen", action="store_true", help="不生成,只用当前数据目录")
    args = ap.parse_args()
    if not args.skip_gen:
        _gen(force=args.force_gen)
        os.environ["FK_DATASET"] = "gen"
    rep = _run_checks()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(_render(rep), encoding="utf-8")
    dh = rep["data_health"].get("summary")
    print("data_health=%s  feature_health=%s  readiness=%s" % (
        dh, rep["feature_health"].get("summary"),
        rep["readiness"].get("overall")))
    print("报告: %s" % OUT)
    return 1 if dh == "fail" else 0


if __name__ == "__main__":
    sys.exit(main())
