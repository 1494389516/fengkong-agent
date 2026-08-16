# -*- coding: utf-8 -*-
"""生产就绪总门禁(P2-4):一次检查回答"现在能不能上"。

检查面:data_health / label_quality / feature_health / model_status /
strategy_status / engine_status / evaluation_status / audit_status /
security_status / degraded_status / budget_status / integration_status。
结果:READY / BLOCKED(硬伤或核心资产未就绪,先修)/ DEGRADED(能力降级
但仍有可信决策路径,可观察运行)。语义拆分:无 champion / 无 active
strategy / 数据硬伤 = BLOCKED(判定路径没有完整资产);引擎本地模式、
缺评估报告等 = DEGRADED(判定路径在,只是降级态)。
"""
import os
import re
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Tuple

from . import tool

ROOT = Path(__file__).resolve().parent.parent.parent


def _git_commit() -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=10)
        return (out.stdout or "").strip()
    except Exception:  # noqa: BLE001
        return ""


def _evaluation_status() -> Tuple[str, str]:
    """评估报告必须对应当前 commit/数据/标签/特征指纹,失败与过期都不能当 ok。"""
    report = ROOT / "out" / "eval_report.md"
    if not report.exists():
        return "warn", "report=缺(out/eval_report.md)"
    try:
        text = report.read_text(encoding="utf-8")
    except OSError:
        return "warn", "report=不可读"
    issues = []
    m = re.search(r"git commit \| `([^`]+)`", text)
    report_commit = m.group(1) if m else ""
    head = _git_commit()
    if head and report_commit and report_commit not in ("unknown", head):
        issues.append("report=陈旧(report=%s, HEAD=%s)" % (report_commit, head))
    m_fail = re.search(r"失败 (\d+)", text)
    if m_fail and int(m_fail.group(1)) > 0:
        issues.append("report=未通过(失败%s)" % m_fail.group(1))
    m_exit = re.search(r"退出码 \| (\d+)", text)
    if not m_exit:
        issues.append("report=缺退出码")
    elif int(m_exit.group(1)) != 0:
        issues.append("report=退出码%s" % m_exit.group(1))
    m_ts = re.search(r"生成时间\(UTC\) \| ([0-9T:Z-]+)", text)
    if m_ts:
        try:
            ts = datetime.strptime(m_ts.group(1).strip(),
                                   "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) - ts > timedelta(days=14):
                issues.append("report=过期(生成%s)" % m_ts.group(1).strip())
        except ValueError:
            issues.append("report=生成时间不可解析")
    m_feat = re.search(r"特征目录 \| `([^`]+)`", text)
    from .featurelib import FEATURE_CATALOG_VERSION
    if not m_feat:
        issues.append("report=缺特征目录")
    elif m_feat.group(1) != FEATURE_CATALOG_VERSION:
        issues.append("report=特征目录过期(report=%s, now=%s)"
                      % (m_feat.group(1), FEATURE_CATALOG_VERSION))
    # 临时 FK_DATA_DIR 是评估隔离,不能拿它跟主报告数据/标签指纹对质
    isolated = bool(os.environ.get("FK_DATA_DIR"))
    m_fp = re.search(r"数据指纹 \| `([^`]+)`", text)
    m_lab = re.search(r"标签指纹 \| `([^`]+)`", text)
    if not m_lab:
        issues.append("report=缺标签指纹")
    if not isolated:
        try:
            from .dataset import dataset_fingerprint
            cur_fp = dataset_fingerprint()
        except Exception:  # noqa: BLE001
            cur_fp = ""
        if m_fp and cur_fp and m_fp.group(1) != cur_fp:
            issues.append("report=数据指纹过期(report=%s, now=%s)"
                          % (m_fp.group(1), cur_fp))
        if m_lab:
            try:
                from .label_lifecycle import label_fingerprint
                live_lab = label_fingerprint()
            except Exception:  # noqa: BLE001
                live_lab = ""
            if live_lab and m_lab.group(1) != live_lab:
                issues.append("report=标签指纹过期(report=%s, now=%s)"
                              % (m_lab.group(1), live_lab))
    if issues:
        return "warn", "; ".join(issues)
    return "ok", "report=有 commit=%s" % (report_commit or "未标注")


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
    ev_level, ev_detail = _evaluation_status()
    add("evaluation_status", ev_level, ev_detail)
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
    # 与 eval/measure_costs.SCHEMA_BUDGET 对齐;agent 不反向依赖 eval
    schema_budget, system_budget = 40500, 5700
    budget_ok = schema_chars <= schema_budget and system_chars <= system_budget
    add("budget_status", "ok" if budget_ok else "fail",
        "schema=%d/%d, system=%d/%d" % (
            schema_chars, schema_budget, system_chars, system_budget))
    integ = _integration()
    add("integration_status", integ["level"], integ["detail"])

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
        "生产就绪总门禁:12 项检查(data/feature/label 健康、模型与策略状态、"
        "引擎通道、评估报告、审计、安全、降级、预算、P2接缝)。BLOCKED=硬伤先修;"
        "DEGRADED=有降级或骨架态(如本地引擎)可观察运行;READY=全部就绪。"
    ),
    parameters={"type": "object", "properties": {}},
)
def production_readiness_check():
    return _readiness()


def _integration() -> Dict:
    """SSO/配置/在线特征/模型/dry-run 接缝:只报告接线,不假装已接生产。"""
    from ..engine import MODEL_URL_ENV, engine_status
    from .datasource import thresholds_path
    from .feature_parity import ONLINE_IMPL_ENV
    sso = bool(os.environ.get("FK_OPERATOR"))
    dry = engine_status()
    online = bool(os.environ.get(ONLINE_IMPL_ENV))
    model = bool(os.environ.get(MODEL_URL_ENV))
    cfg = thresholds_path().exists()
    wired = {
        "sso": sso, "config_center": cfg, "online_features": online,
        "model_service": model, "dry_run": dry.get("mode") == "remote_engine",
    }
    if all(wired.values()):
        level = "ok"
    elif not wired["dry_run"]:
        level = "degraded"
    else:
        level = "warn"
    detail = " ".join("%s=%s" % (k, "on" if v else "off")
                      for k, v in wired.items())
    return {"level": level, "detail": detail, "seams": {
        "sso": {"wired": sso, "source": "FK_OPERATOR|X-Operator"},
        "config_center": {"wired": cfg, "source": "policy_versions"},
        "online_features": {"wired": online, "source": ONLINE_IMPL_ENV},
        "model_service": {"wired": model,
                          "source": MODEL_URL_ENV if model else "model_scores.json"},
        "dry_run": {"wired": wired["dry_run"], "source": dry.get("mode")},
    }}


@tool(
    name="integration_status",
    description=(
        "P2接缝:SSO/策略配置/在线特征/模型服务/dry-run是否接线。"
        "只报告不改判定;未接远程即 degraded。"
    ),
    parameters={"type": "object", "properties": {}},
)
def integration_status():
    return _integration()
