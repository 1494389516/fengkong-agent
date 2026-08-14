#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""评估报告生成器:把 run_eval 的结构化记录沉淀成可追溯的 markdown 报告。

评估结果不能只活在终端里 —— 本模块解决三个问题:
  1. 可追溯:报告头写死 git commit + 数据指纹 + 生成时间,
     "这份报告评的是哪版代码、哪批数据" 一目了然;
  2. 可沉淀:分层明细 + 失败清单落盘,CI 可存档、可对比历史;
  3. 可演示:总览 + 成本面 + agent 层四维,一张报告讲清全貌。

用法:
  python3 eval/run_eval.py --offline --report out/eval_report.md   # 顺手出报告
  python3 eval/report.py                                           # 只出报告(离线层)
  失败时报告头部标 ❌,与退出码联动。
"""
import hashlib
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def git_commit() -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=10)
        return out.stdout.strip() or "unknown"
    except Exception:  # noqa: BLE001 报告生成失败不该掀翻评估
        return "unknown"


def data_fingerprint() -> str:
    """数据指纹:data/*.json|jsonl 的 (名, mtime_ns, size) 哈希。
    数据变了指纹必变 —— 报告与数据集的绑定关系因此不可伪造。"""
    d = ROOT / "data"
    h = hashlib.sha256()
    files = sorted(d.glob("*.json")) + sorted(d.glob("*.jsonl"))
    if not files:
        return "empty"
    for p in files:
        st = p.stat()
        h.update(("%s:%d:%d;" % (p.name, st.st_mtime_ns, st.st_size))
                 .encode("utf-8"))
    return h.hexdigest()[:16]


def _structural_metrics() -> dict:
    """结构性成本快照(schema/system 字符量),报告的成本面数据源。"""
    try:
        from measure_costs import structural_sizes
        return structural_sizes()
    except Exception:  # noqa: BLE001 依赖未装时成本面降级为空
        return {}


def _totals(records) -> tuple:
    total = sum(r["total"] for r in records)
    fails = sum(r["failures"] for r in records)
    return total, fails


def render_report(records: list, offline: bool = False,
                  failures: int = -1) -> str:
    """把结构化记录渲染成 markdown 报告文本。failures<0 时自行统计。"""
    total, fails = _totals(records)
    if failures < 0:
        failures = fails
    metrics = _structural_metrics()
    status = "❌ 有失败" if failures else "✅ 全部通过"
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    lines = [
        "# 风控 Agent 评估报告",
        "",
        "| 元信息 | 值 |",
        "|---|---|",
        "| 生成时间(UTC) | %s |" % now,
        "| git commit | `%s` |" % git_commit(),
        "| 数据指纹 | `%s` |" % data_fingerprint(),
        "| 模式 | %s |" % ("offline(第 1 层 + 离线层)" if offline else "完整"),
        "| 工具数 | %s |" % metrics.get("tool_count", "-"),
        "",
        "## 总览",
        "",
        "**%s** — 断言 %d 项,通过 %d,失败 %d,通过率 %.1f%%" % (
            status, total, total - failures, failures,
            100.0 * (total - failures) / total if total else 0.0),
        "",
        "## 结构性成本(token 预算面)",
        "",
        "| 指标 | 现值 | 预算 |",
        "|---|---|---|",
    ]
    if metrics:
        lines += [
            "| 工具 schema | %d chars | 18000 |" % metrics["schemas_chars"],
            "| system prompt | %d chars | 3600 |" % metrics["system_chars"],
        ]
    else:
        lines.append("| (依赖未装,成本面不可用) | - | - |")

    lines += ["", "## 分层明细", "",
              "| 层 | 断言 | 失败 | 状态 |",
              "|---|---|---|---|"]
    for r in records:
        note = ("(%s)" % r["note"]) if r.get("note") else ""
        lines.append("| %s %s | %d | %d | %s |" % (
            r["layer"], note, r["total"], r["failures"],
            "✅" if r["failures"] == 0 else "❌"))

    failed_checks = [(r["layer"], c["name"]) for r in records
                     for c in r["checks"] if not c["ok"]]
    lines += ["", "## 失败清单", ""]
    if failed_checks:
        for layer, name in failed_checks:
            lines.append("- ❌ %s — %s" % (layer, name))
    else:
        lines.append("无。")
    lines += ["", "## agent 层(第 2+3 层)", ""]
    agent = [r for r in records if r["layer"].startswith("agent 层")]
    if agent and agent[0].get("note"):
        lines.append("> %s — 四维基线(结论/取证轨迹/轨迹效率/token 预算)"
                     "待实弹运行后回填本段。" % agent[0]["note"])
    else:
        lines.append("> 见逐案例打印;四维指标待 agent_runs.jsonl 聚合"
                     "(eval/agent_metrics.py)。")
    lines += ["", "## 已知边界提醒", "",
              "- 数据为合成样本,指标绝对值无外推意义;",
              "- 本报告仅描述评估本身,不构成上线结论;对账未通过时模拟类"
              "结论不可作为变更依据。", ""]
    return "\n".join(lines)


def write_report(path, records: list, offline: bool = False,
                 failures: int = -1) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(render_report(records, offline=offline, failures=failures),
                 encoding="utf-8")


def refresh_agent_card(card_path=None) -> int:
    """用最新评估数字刷新 AGENT_CARD.md「当前评估指标」表。按行正则替换
    单元格(而非一次性占位符),重复执行幂等。返回刷新的行数。"""
    import re

    p = Path(card_path) if card_path else ROOT / "AGENT_CARD.md"
    if not p.exists():
        return 0
    metrics = _structural_metrics()
    from agent.tools import schemas  # 工具数取真实注册表
    values = {
        "git commit": "`%s`" % git_commit(),
        "数据指纹": "`%s`" % data_fingerprint(),
        "工具数": str(len(schemas())),
        "工具 schema": "%s chars(预算 18000)" % metrics.get("schemas_chars", "-"),
        "system prompt": "%s chars(预算 3600)" % metrics.get("system_chars", "-"),
        "最近刷新(UTC)": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    text = p.read_text(encoding="utf-8")
    refreshed = 0
    for label, val in values.items():
        new_text, n = re.subn(
            r"(\| %s \|)[^|\n]*(?=\|)" % re.escape(label),
            r"\1 %s " % val.replace("\\", "\\\\"), text)
        if n:
            text = new_text
            refreshed += n
    p.write_text(text, encoding="utf-8")
    return refreshed


def main() -> int:
    import run_eval
    failures, records = run_eval.run_all(offline=True)
    out = ROOT / "out" / "eval_report.md"
    write_report(out, records, offline=True, failures=failures)
    print("报告已写入: %s" % out)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
