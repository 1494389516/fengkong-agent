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


def _champion_model() -> dict:
    """当前 champion 模型摘要(默认数据集登记簿),供报告/档案展示。"""
    try:
        from agent.tools.dataset import dataset_fingerprint
        from agent.tools.datasource import data_dir
        import json as _json
        p = data_dir() / "model_registry.json"
        if not p.exists():
            return {}
        items = _json.loads(p.read_text(encoding="utf-8"))
        ch = [m for m in items if m.get("status") == "champion"]
        if not ch:
            return {}
        m = ch[0]
        met = m.get("metrics") or {}
        return {"name": m["name"], "version": m["version"],
                "auc": met.get("auc"), "ks": met.get("ks"),
                "sample_count": met.get("sample_count"),
                "train_fingerprint": m.get("train_fingerprint"),
                "deployed_at": m.get("deployed_at"),
                "dataset_fingerprint": dataset_fingerprint()}
    except Exception:  # noqa: BLE001 报告生成失败不该掀翻评估
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
        from measure_costs import SCHEMA_BUDGET, SYSTEM_PROMPT_BUDGET
        lines += [
            "| 工具 schema | %d chars | %d |" % (
                metrics["schemas_chars"], SCHEMA_BUDGET),
            "| system prompt | %d chars | %d |" % (
                metrics["system_chars"], SYSTEM_PROMPT_BUDGET),
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
    ch = _champion_model()
    lines += ["", "## 模型评估(champion)", ""]
    if ch:
        lines += [
            "| 指标 | 值 |",
            "|---|---|",
            "| champion | `%s %s` |" % (ch["name"], ch["version"]),
            "| auc / ks | %s / %s |" % (ch.get("auc"), ch.get("ks")),
            "| 评估样本数 | %s |" % ch.get("sample_count"),
            "| 训练集指纹 | `%s` |" % ch.get("train_fingerprint"),
            "| 上线时间 | %s |" % ch.get("deployed_at"),
        ]
    else:
        lines.append("> 无 champion 登记(模型生命周期未走到上线)。")
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


def _assert_total(records) -> int:
    """本次评估的断言总数(records 汇总);无 records 时返回 0(表示未知,
    调用方跳过依赖它的替换)。"""
    if not records:
        return 0
    return sum(r.get("total", 0) for r in records)


def refresh_agent_card(card_path=None, records=None) -> int:
    """用最新系统状态刷新 AGENT_CARD.md(P0-4,数字全部自动取,不人工维护):
      指标表(commit/指纹/工具数/schema/system/断言数)+ 能力总览"工具层 N 个"。
    按行正则替换,重复执行幂等。返回刷新的行数。"""
    import re

    p = Path(card_path) if card_path else ROOT / "AGENT_CARD.md"
    if not p.exists():
        return 0
    metrics = _structural_metrics()
    from agent.tools import schemas  # 工具数取真实注册表
    from measure_costs import SCHEMA_BUDGET, SYSTEM_PROMPT_BUDGET
    ch = _champion_model()
    n_tools = len(schemas())
    n_asserts = _assert_total(records)
    n_cases = 0
    try:
        import json as _j
        cases = _j.loads((ROOT / "eval" / "cases.json").read_text(encoding="utf-8"))
        n_cases = len(cases.get("agent_cases", []))
    except Exception:  # noqa: BLE001 案例数缺失不阻塞其余同步
        pass
    values = {
        "git commit": "`%s`" % git_commit(),
        "数据指纹": "`%s`" % data_fingerprint(),
        "工具数": str(n_tools),
        "工具 schema": "%s chars(预算 %d)" % (
            metrics.get("schemas_chars", "-"), SCHEMA_BUDGET),
        "system prompt": "%s chars(预算 %d)" % (
            metrics.get("system_chars", "-"), SYSTEM_PROMPT_BUDGET),
        "最近刷新(UTC)": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "MODEL_CHAMPION": ("无" if not ch else "%s %s" % (ch["name"], ch["version"])),
        "MODEL_AUC": "-" if not ch else ch.get("auc"),
        "MODEL_KS": "-" if not ch else ch.get("ks"),
        "MODEL_SAMPLE": "-" if not ch else ch.get("sample_count"),
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
    # 指标表"离线断言"行:有则刷新,无则插在工具数行之后
    if n_asserts:
        row = "| 离线断言 | %d 项 |" % n_asserts
        if "| 离线断言 |" in text:
            new_text, n = re.subn(r"\| 离线断言 \|[^|\n]*(?=\|)",
                                  "| 离线断言 | %d 项 " % n_asserts, text)
            text, refreshed = new_text, refreshed + n
        else:
            idx = text.find("| 工具数 |")
            if idx >= 0:
                eol = text.find("\n", idx)
                text = text[:eol + 1] + row + "\n" + text[eol + 1:]
                refreshed += 1
    # 叙述文本:"工具层 N 个(`N`)" —— 精确模式,不全局替换反引号数字
    # (全局 r"`\d+`" 会误伤文档里其它反引号包裹的整数,如阈值/预算数字)
    text, n = re.subn(r"工具层 \d+ 个\(\`\d+\`\)",
                      "工具层 %d 个(\`%d\`)" % (n_tools, n_tools), text)
    refreshed += n
    if n_cases:
        text, n = re.subn(r"\(\d+ 个黄金案例", "(%d 个黄金案例" % n_cases, text)
        refreshed += n
        text, n = re.subn(r"agent 层 \d+ 案例尚未实弹",
                          "agent 层 %d 案例尚未实弹" % n_cases, text)
        refreshed += n
    p.write_text(text, encoding="utf-8")
    return refreshed


def refresh_readme(readme_path=None, records=None) -> int:
    """刷新 README.md 系统快照(P0-4):
      - AUTO-SYNC 标记之间的快照块整块重写(commit/工具数/schema/system/指纹/
        断言数/案例数/刷新时间);
      - "工具层(N 个"、"170+ 项"、"N 个黄金案例" 与现状对齐。
    返回刷新的行数。"""
    import re
    import json as _j

    p = Path(readme_path) if readme_path else ROOT / "README.md"
    if not p.exists():
        return 0
    metrics = _structural_metrics()
    from agent.tools import schemas
    n_tools = len(schemas())
    n_asserts = _assert_total(records)
    n_cases = 0
    try:
        cases = _j.loads((ROOT / "eval" / "cases.json").read_text(encoding="utf-8"))
        n_cases = len(cases.get("agent_cases", []))
    except Exception:  # noqa: BLE001 案例数缺失不阻塞其余同步
        pass
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    block = "\n".join([
        "<!-- AUTO-SYNC:FK-DOC-SNAPSHOT-START -->",
        "## 系统快照(自动生成,勿手改;`python3 eval/run_eval.py --report` 刷新)",
        "",
        "| 项 | 值 |",
        "|---|---|",
        "| git commit | `%s` |" % git_commit(),
        "| 工具数 | %d |" % n_tools,
        "| 工具 schema | %d chars |" % metrics.get("schemas_chars", 0),
        "| system prompt | %d chars |" % metrics.get("system_chars", 0),
        "| 数据指纹 | `%s` |" % data_fingerprint(),
        "| 离线断言数 | %d |" % (n_asserts or 0),
        "| agent 黄金案例 | %d |" % n_cases,
        "| 最近刷新(UTC) | %s |" % now,
        "",
        "<!-- AUTO-SYNC:FK-DOC-SNAPSHOT-END -->",
    ])
    text = p.read_text(encoding="utf-8")
    refreshed = 0
    if "AUTO-SYNC:FK-DOC-SNAPSHOT-START" in text:
        text, n = re.subn(
            r"<!-- AUTO-SYNC:FK-DOC-SNAPSHOT-START -->.*?"
            r"<!-- AUTO-SYNC:FK-DOC-SNAPSHOT-END -->",
            block, text, count=1, flags=re.S)
        refreshed += 1
    else:
        m = re.search(r"\n## ", text)
        pos = m.start() if m else len(text)
        text = text[:pos] + "\n" + block + text[pos:]
        refreshed += 1
    text, n = re.subn(r"工具层\(\d+ 个", "工具层(%d 个" % n_tools, text)
    refreshed += n
    if n_asserts:
        text, n = re.subn(r"170\+ 项", "%d 项" % n_asserts, text)
        refreshed += n
        # 叙述里手写的离线断言数(历史 185/170 等)跟本次评估对齐,避免快照与正文劈叉
        for pat, repl in (
            (r"当前 \d+ 项,全离线零 token",
             "当前 %d 项,全离线零 token" % n_asserts),
            (r"不需要 key,\d+ 项断言",
             "不需要 key,%d 项断言" % n_asserts),
            (r"eval/ \d+ 项离线断言",
             "eval/ %d 项离线断言" % n_asserts),
            (r"离线\(\d+ 项,零 token",
             "离线(%d 项,零 token" % n_asserts),
        ):
            text, n = re.subn(pat, repl, text)
            refreshed += n
    if n_cases:
        text, n = re.subn(r"\d+ 个黄金案例", "%d 个黄金案例" % n_cases, text)
        refreshed += n
    p.write_text(text, encoding="utf-8")
    return refreshed


def refresh_docs(records=None) -> int:
    """P0-4:AGENT_CARD + README 一次同步(指标/工具数/断言数/案例数)。"""
    return refresh_agent_card(records=records) + refresh_readme(records=records)


def main() -> int:
    import run_eval
    failures, records = run_eval.run_all(offline=True)
    out = ROOT / "out" / "eval_report.md"
    write_report(out, records, offline=True, failures=failures)
    refresh_docs(records)  # P0-4:AGENT_CARD/README 系统快照自动同步
    print("报告已写入: %s" % out)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
