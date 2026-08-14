# -*- coding: utf-8 -*-
"""决策血缘:给任何一条生产决策回答"为什么"。

统一血缘记录(data/decision_lineage.jsonl,运行时文件):
  decision_id / event_id(输入指纹)/ uid / engine_source / policy_version /
  strategy_version / model_version / feature_snapshot_version /
  input_fingerprint / decision / hits / degraded / approver / timestamp

写入方:
  - serve.py /decide(生产决策路径,approver="serve")
  - 其他判定路径按需调用 write_lineage(approver 注明来源)
回放(replay)不写血缘 —— 回放是反事实,零副作用纪律优先。

查询方:
  - decision_trace:按输入指纹/uid+ts 查已落库记录;查不到则现场解释并
    标注"未落库,仅实时解释"
  - decision_explain:对事件做一次带完整血缘的实时解释(不落库,只读)
"""
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from . import tool
from .datasource import data_dir

LINEAGE_FILE = "decision_lineage.jsonl"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _lineage_path():
    return data_dir() / LINEAGE_FILE


def event_fingerprint(event: Dict[str, Any]) -> str:
    from ..replay import event_fingerprint as _fp
    return _fp(event)


def write_lineage(event: Dict[str, Any], decision: Dict[str, Any],
                  approver: str = "serve") -> str:
    """落一条生产决策血缘。decision 须含 action/hits/policy_version/source;
    返回 decision_id。尽力而为:血缘写失败不掀翻决策路径。"""
    fp = event_fingerprint(event)
    rec = {
        "decision_id": "%s-%s" % (fp, _now_iso()[:19].replace(":", "")),
        "event_id": fp,
        "uid": event.get("uid"),
        "engine_source": decision.get("source", "local_rules"),
        "policy_version": decision.get("policy_version"),
        "strategy_version": decision.get("strategy_version"),
        "model_version": decision.get("model_version"),
        "feature_snapshot_version": decision.get("feature_snapshot_version"),
        "input_fingerprint": fp,
        "decision": decision.get("action"),
        "hits": decision.get("hits", []),
        "degraded": bool(decision.get("degraded")),
        "approver": approver,
        "timestamp": _now_iso(),
    }
    try:
        p = _lineage_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:  # noqa: BLE001
        pass
    return rec["decision_id"]


def _load_lineage() -> list:
    p = _lineage_path()
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def _lineage_context(event: Dict[str, Any], decision: Dict[str, Any]) -> Dict[str, Any]:
    """给判定结果补全血缘字段(解释/落库共用)。"""
    from .featurelib import FEATURE_CATALOG_VERSION
    from .model_registry import _load as _mload
    from .strategy_registry import _load as _sload
    decision = dict(decision)
    decision.setdefault("feature_snapshot_version", FEATURE_CATALOG_VERSION)
    champions = [m for m in _mload() if m.get("status") == "champion"]
    decision["model_version"] = (decision.get("model_version")
                                 or ("%s %s" % (champions[0]["name"],
                                                champions[0]["version"])
                                     if champions else None))
    actives = [s for s in _sload() if s.get("status") == "active"]
    decision["strategy_version"] = (decision.get("strategy_version")
                                    or ("%s %s" % (actives[0]["strategy_name"],
                                                   actives[0]["version"])
                                        if actives else None))
    return decision


@tool(
    name="decision_explain",
    description=(
        "对事件做一次带完整血缘的实时解释(只读,不落库):判定结果 + 输入指纹"
        "+ 策略版本/策略名/模型名(champion)/特征目录版本 + 引擎来源与降级标记。"
        "回答'这条决策为什么、当时用的是哪套策略和模型'。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "event": {"type": "object", "description": "待解释事件(字段同 rule_eval)"},
        },
        "required": ["event"],
    },
)
def decision_explain(event: Dict[str, Any]):
    from ..engine import evaluate_event
    from .rules import rule_eval  # noqa: F401 确保注册
    decision = evaluate_event(event, use_current_policy=True)
    decision = _lineage_context(event, decision)
    return {
        "event_id": event_fingerprint(event),
        "input_fingerprint": event_fingerprint(event),
        "decision": decision["action"],
        "hits": decision["hits"],
        "engine_source": decision.get("source"),
        "degraded": bool(decision.get("degraded")),
        "policy_version": decision.get("policy_version"),
        "strategy_version": decision.get("strategy_version"),
        "model_version": decision.get("model_version"),
        "feature_snapshot_version": decision.get("feature_snapshot_version"),
        "explained_at": _now_iso(),
        "note": "实时解释,未落库(落库走 serve/decide 决策路径)",
    }


@tool(
    name="decision_trace",
    description=(
        "按事件指纹或 uid+ts 查已落库的生产决策血缘记录(决策/命中规则/策略·"
        "模型版本/降级/审批来源/时间);查不到返回现场解释并标注'未落库'。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "event": {"type": "object", "description": "事件(按输入指纹匹配)"},
            "uid": {"type": "string", "description": "也可按 uid 查(与 ts 配合)"},
            "ts": {"type": "number", "description": "事件时间戳,与 uid 配合"},
        },
        "required": ["event"],
    },
)
def decision_trace(event: Dict[str, Any], uid: str = "", ts: float = None):
    fp = event_fingerprint(event)
    records = _load_lineage()
    hits = [r for r in records if r.get("input_fingerprint") == fp]
    if not hits and uid and ts:
        hits = [r for r in records
                if r.get("uid") == uid and r.get("timestamp", "").startswith(
                    datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d"))]
    if hits:
        rec = hits[-1]  # 最新一条
        return {"found": True, "record": rec,
                "decision_id": rec["decision_id"], "approver": rec["approver"]}
    explained = decision_explain(event)
    explained["found"] = False
    explained["note"] = "未落库:仅实时解释(生产决策血缘由 serve/decide 落库)"
    return explained
