# -*- coding: utf-8 -*-
"""事故工作流:把对账差异/漂移/数据问题从"队列"升级为"事故治理"。

incident 绑定证据(decision_ids / mismatch_ids / affected_strategy /
affected_model),记录根因与处置 —— mismatch 因此真正进入事故治理闭环。
类型:engine_mismatch / feature_drift / label_drift / model_drift /
policy_sync_lag / agent_policy_violation / data_quality / latency。

状态:open -> resolved(记录 root_cause + resolution + owner + 时间)。
存储:data/incidents.json(运行时文件)。运营台账,与审批无关,但全部
execute 级调用由 capability 层留 security audit。
"""
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional

from . import tool
from .datasource import data_dir

INCIDENT_FILE = "incidents.json"
INCIDENT_TYPES = ("engine_mismatch", "feature_drift", "label_drift",
                  "model_drift", "policy_sync_lag", "agent_policy_violation",
                  "data_quality", "latency")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _path():
    return data_dir() / INCIDENT_FILE


def _load() -> List[Dict]:
    p = _path()
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else []


def _save(items: List[Dict]) -> None:
    from .datasource import atomic_write_json
    atomic_write_json(_path(), items)


def _mismatch_keys() -> set:
    p = data_dir() / "mismatch_queue.json"
    if not p.exists():
        return set()
    try:
        return {it.get("key") for it in json.loads(p.read_text(encoding="utf-8"))}
    except Exception:  # noqa: BLE001 队列损坏不掀翻事故工作流
        return set()


@tool(
    name="incident_open",
    description=(
        "开事故单:类型(engine_mismatch/feature_drift/label_drift/model_drift/"
        "policy_sync_lag/agent_policy_violation/data_quality/latency)+ 证据"
        "(decision_ids、mismatch_ids 必须存在于对账工单,绑定关系可追)。"
        "返回 incident_id,后续用 incident_update/incident_resolve。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "incident_type": {"type": "string", "enum": list(INCIDENT_TYPES),
                              "description": "事故类型"},
            "summary": {"type": "string", "description": "事故摘要"},
            "decision_ids": {"type": "array", "items": {"type": "string"},
                             "description": "关联决策血缘 id(可空)"},
            "mismatch_ids": {"type": "array", "items": {"type": "string"},
                             "description": "关联对账工单键(须存在于 mismatch_queue)"},
            "affected_strategy": {"type": "string", "description": "受影响策略(可空)"},
            "affected_model": {"type": "string", "description": "受影响模型(可空)"},
            "owner": {"type": "string", "description": "负责人(可空)"},
        },
        "required": ["incident_type", "summary"],
    },
)
def incident_open(incident_type: str, summary: str, decision_ids: List[str] = None,
                  mismatch_ids: List[str] = None, affected_strategy: str = "",
                  affected_model: str = "", owner: str = ""):
    if incident_type not in INCIDENT_TYPES:
        return {"error": "未知事故类型: %s" % incident_type}
    mismatch_ids = mismatch_ids or []
    if mismatch_ids:
        known = _mismatch_keys()
        bad = [k for k in mismatch_ids if k not in known]
        if bad:
            return {"error": "mismatch_ids 不在对账工单中: %s(先 consistency_check)"
                             % bad}
    items = _load()
    incident_id = max((i["incident_id"] for i in items), default=0) + 1
    rec = {
        "incident_id": incident_id,
        "incident_type": incident_type,
        "summary": summary,
        "decision_ids": decision_ids or [],
        "mismatch_ids": mismatch_ids,
        "affected_strategy": affected_strategy,
        "affected_model": affected_model,
        "status": "open",
        "owner": owner,
        "created_at": _now_iso(),
        "resolved_at": None,
        "root_cause": None,
        "resolution": None,
        "notes": [],
    }
    items.append(rec)
    _save(items)
    return {"status": "open", "incident_id": incident_id}


@tool(
    name="incident_update",
    description=("给事故单追加调查/进展记录(notes)。"),
    parameters={
        "type": "object",
        "properties": {
            "incident_id": {"type": "integer", "description": "事故单 id"},
            "note": {"type": "string", "description": "进展说明"},
        },
        "required": ["incident_id", "note"],
    },
)
def incident_update(incident_id: int, note: str):
    items = _load()
    for i in items:
        if i["incident_id"] == incident_id:
            if i["status"] == "resolved":
                return {"error": "事故已结案,不可追加(重开请开新单)"}
            i["notes"].append({"ts": _now_iso(), "note": note})
            _save(items)
            return {"status": "updated", "incident_id": incident_id}
    return {"error": "事故单不存在: #%d" % incident_id}


@tool(
    name="incident_resolve",
    description=(
        "结案:记录根因(root_cause)与处置(resolution),状态置 resolved。"
        "已结案不可重复结案。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "incident_id": {"type": "integer", "description": "事故单 id"},
            "root_cause": {"type": "string", "description": "根因分析"},
            "resolution": {"type": "string", "description": "处置结果"},
            "owner": {"type": "string", "description": "结案人(可空)"},
        },
        "required": ["incident_id", "root_cause", "resolution"],
    },
)
def incident_resolve(incident_id: int, root_cause: str, resolution: str,
                     owner: str = ""):
    items = _load()
    for i in items:
        if i["incident_id"] == incident_id:
            if i["status"] == "resolved":
                return {"error": "事故已结案,不可重复结案: #%d" % incident_id}
            i["status"] = "resolved"
            i["root_cause"] = root_cause
            i["resolution"] = resolution
            i["resolved_at"] = _now_iso()
            if owner:
                i["owner"] = owner
            _save(items)
            return {"status": "resolved", "incident_id": incident_id}
    return {"error": "事故单不存在: #%d" % incident_id}


@tool(
    name="incident_list",
    description=(
        "列出事故单:按状态(open/resolved)或类型过滤,含证据绑定/根因/处置。"
        "mismatch 真正进入事故治理的查询入口。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "status": {"type": "string", "enum": ["", "open", "resolved"],
                       "description": "可选:按状态过滤"},
            "incident_type": {"type": "string", "enum": list(INCIDENT_TYPES),
                              "description": "可选:按类型过滤"},
        },
    },
)
def incident_list(status: str = "", incident_type: str = ""):
    items = _load()
    if status:
        items = [i for i in items if i["status"] == status]
    if incident_type:
        items = [i for i in items if i["incident_type"] == incident_type]
    return {"count": len(items), "incidents": items}
