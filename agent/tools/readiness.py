# -*- coding: utf-8 -*-
"""生产就绪总门禁(P2-4):一次检查回答"现在能不能上"。

检查面:data_health / label_quality / feature_health / model_status /
strategy_status / engine_status / evaluation_status / audit_status /
security_status / degraded_status / budget_status。
结果:READY / BLOCKED(硬伤或核心资产未就绪,先修)/ DEGRADED(能力降级
但仍有可信决策路径,可观察运行)。语义拆分:无 champion / 无 active
strategy / 数据硬伤 = BLOCKED(判定路径没有完整资产);引擎本地模式、
缺评估报告等 = DEGRADED(判定路径在,只是降级态)。
"""
from pathlib import Path
from typing import Dict

from . import tool

ROOT = Path(__file__).resolve().parent.parent.parent


def _readiness() -> Dict:
    from .capability import _audit_records
    from .dataset import dataset_fingerprint
    from .datasource import data_dir
    from ..engine import engine_status
    from .feature_health import feature_health_check
    from .health import data_health_check
    from .label_quality_proxy import label_conflicts
    from .model_registry import _load as _mload
    from .strategy_registry import _load as _sload
    import json as _json

    checks = {}
    verdicts = []

    def add(name, level, detail):
        checks[name] = {"level": level, "detail": detail}
        verdicts.append(level)

    dh = data_health_check()
    add("data_health", dh["summary"],
        "issues=%d" % dh.get("issues_total", 0))
    fh = feature_health_check()
    add("feature_health", fh["summary"], "accounts=%d" % fh.get("accounts_checked", 0))
    conflicts = label_conflicts()
    add("label_quality", "warn" if conflicts else "ok",
        "conflicts=%d(只报不改)" % len(conflicts))
    models = _mload()
    champions = [m for m in models if m.get("status") == "champion"]
    # 语义修正(评审 P0-5 方向):BLOCKED = 核心决策资产未就绪 ——
    # 无 champion(判定路径没有模型层)/无 active strategy(没有经治理
    # 生效的策略声明)与数据硬伤同级,不是"还能凑合观察"的降级态;
    # DEGRADED 只留给"能力降级但仍有可信决策路径"(本地引擎/缺报告等)。
    add("model_status", "ok" if champions else "fail",
        "champion=%s(核心资产:判定路径的模型层)" % (champions[0]["name"] if champions else "无"))
    strategies = _sload()
    actives = [s for s in strategies if s.get("status") == "active"]
    add("strategy_status", "ok" if actives else "fail",
        "active=%s(核心资产:经治理生效的策略声明)" % (len(actives),))
    es = engine_status()
    add("engine_status", "ok" if es["mode"] == "remote_engine" else "degraded",
        es["mode"])
    report = ROOT / "out" / "eval_report.md"
    add("evaluation_status", "ok" if report.exists() else "warn",
        "report=%s" % ("有" if report.exists() else "缺(out/eval_report.md)"))
    audit = data_dir() / "audit.jsonl"
    add("audit_status", "ok" if audit.exists() else "warn",
        "audit=%s" % ("有" if audit.exists() else "尚无审批记录"))
    sec = _audit_records()
    denied = sum(1 for r in sec if r.get("kind") == "denied")
    add("security_status", "ok" if sec else "warn",
        "audit=%d条,denied=%d" % (len(sec), denied))
    lineage = data_dir() / "decision_lineage.jsonl"
    degraded = 0
    if lineage.exists():
        for line in lineage.read_text(encoding="utf-8").splitlines():
            try:
                if _json.loads(line).get("degraded"):
                    degraded += 1
            except _json.JSONDecodeError:
                pass
    add("degraded_status", "ok" if degraded == 0 else "degraded",
        "degraded_decisions=%d" % degraded)
    from . import schemas as _schemas
    schema_chars = len(_json.dumps(_schemas(), ensure_ascii=False))
    system_chars = len((ROOT / "agent" / "prompts" / "system.md")
                       .read_text(encoding="utf-8"))
    budget_ok = schema_chars <= 37500 and system_chars <= 5250
    add("budget_status", "ok" if budget_ok else "fail",
        "schema=%d/37500, system=%d/5250" % (schema_chars, system_chars))

    if "fail" in verdicts or "blocked" in verdicts:
        overall = "BLOCKED"
    elif "degraded" in verdicts:
        overall = "DEGRADED"
    elif "warn" in verdicts:
        overall = "DEGRADED"
    else:
        overall = "READY"
    return {"overall": overall, "checks": checks,
            "dataset_fingerprint": dataset_fingerprint()}


@tool(
    name="production_readiness_check",
    description=(
        "生产就绪总门禁:11 项检查(data/feature/label 健康、模型与策略状态、"
        "引擎通道、评估报告、审计、安全、降级、预算)。BLOCKED=硬伤先修;"
        "DEGRADED=有降级或骨架态(如本地引擎)可观察运行;READY=全部就绪。"
    ),
    parameters={"type": "object", "properties": {}},
)
def production_readiness_check():
    return _readiness()
