# -*- coding: utf-8 -*-
"""Agent action governance: external policy decision point + trajectory guard.

This module deliberately sits outside prompts. The model may request an action,
but only server-issued scope plus deterministic policy can authorize it.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from contextvars import ContextVar
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .tools import capability
from .tools.datasource import append_jsonl, agent_audit_dir, file_lock

POLICY_VERSION = "agent-governance-v2"
UNTRUSTED = frozenset({"external", "user_provided", "llm_derived"})
PRODUCTION_LEVELS = frozenset({"execute"})
SOURCE_TRUST = {
    "get_event_evidence": "server_evidence",
    "account_profile": "server_evidence",
    "feature_stats": "server_evidence",
    "graph_relations": "server_evidence",
    "rule_eval": "server_evidence",
    "search_risk_knowledge": "external",
}

@dataclass(frozen=True)
class PolicyDecision:
    outcome: str
    reason_code: str
    matched_rule: str
    policy_version: str = POLICY_VERSION

@dataclass(frozen=True)
class ActionEnvelope:
    run_id: str
    tool_name: str
    capability: str
    args_hash: str
    principal: str = ""
    tenant: str = ""
    dataset: str = ""
    evidence_trust: tuple = ()
    dependencies_digest: str = ""
    effect: str = ""
    input_schema_digest: str = ""

_trajectory: ContextVar[Optional[Dict[str, Any]]] = ContextVar("fk_governance_trajectory", default=None)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def reset_trajectory(run_id: Optional[str] = None) -> str:
    rid = run_id or uuid.uuid4().hex
    _trajectory.set({"run_id": rid, "trust": [], "tools": [], "last_hash": ""})
    return rid


from contextlib import contextmanager
import copy

@contextmanager
def bind_trajectory(state):
    token = _trajectory.set(copy.deepcopy(state))
    try:
        yield
    finally:
        _trajectory.reset(token)


def restore_trajectory(state):
    _trajectory.set(copy.deepcopy(state))


def trajectory_snapshot() -> Dict[str, Any]:
    state = _trajectory.get()
    if state is None:
        reset_trajectory()
        state = _trajectory.get()
    return {
        "run_id": state["run_id"],
        "trust": list(state["trust"]),
        "tools": list(state["tools"]),
        "evidence": copy.deepcopy(state.get("evidence", {})),
    }


def _scope_fields() -> Dict[str, str]:
    scope = capability.get_scope()
    if scope is None:
        return {"principal": "", "tenant": "", "dataset": ""}
    return {
        "principal": scope.principal,
        "tenant": scope.tenant,
        "dataset": scope.dataset,
    }


def _envelope(tool_name: str, arguments: Dict[str, Any]) -> ActionEnvelope:
    state = trajectory_snapshot()
    from .tool_provenance import verified_binding
    binding=verified_binding(tool_name,arguments)
    from .tools import _REGISTRY
    from .tool_contracts import descriptor
    contract=descriptor(tool_name,_REGISTRY.get(tool_name,{}).get('parameters',{}),capability.level_of(tool_name))
    return ActionEnvelope(
        run_id=state["run_id"],
        tool_name=tool_name,
        capability=capability.level_of(tool_name),
        args_hash=_digest(arguments),
        evidence_trust=tuple(state["trust"]),
        dependencies_digest=binding["dependencies_digest"] if binding else "",
        effect=contract.effect,input_schema_digest=contract.schema_digest,
        **_scope_fields(),
    )


def _append_audit(envelope: ActionEnvelope, decision: PolicyDecision, phase: str,
                  result_hash: str = "") -> None:
    """Append a hash-chained record.

    The chain detects mutation/removal inside the retained log. Detecting tail
    truncation requires anchoring the last hash in an external/WORM system.
    """
    path = agent_audit_dir() / "governance_audit.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with file_lock(path.parent / ".governance_chain"):
        previous = ""
        if path.exists():
            # Audit is correctness-critical but should not become O(n) per tool
            # call as the log grows. Read only a bounded tail for the last line.
            with open(path, "rb") as fh:
                fh.seek(0, 2)
                size = fh.tell()
                fh.seek(max(0, size - 65536))
                tail = fh.read().decode("utf-8", errors="replace")
            lines = [x for x in tail.splitlines() if x.strip()]
            if lines:
                try:
                    previous = json.loads(lines[-1]).get("record_hash", "")
                except json.JSONDecodeError:
                    previous = "CORRUPT_PREVIOUS_RECORD"
        body = {
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "phase": phase,
            "envelope": asdict(envelope),
            "decision": asdict(decision),
            "result_hash": result_hash,
            "previous_hash": previous,
        }
        body["record_hash"] = _digest(body)
        append_jsonl(path, body)


def decide(tool_name: str, arguments: Dict[str, Any], is_registered: bool) -> PolicyDecision:
    # Existing capability enforcement remains authoritative and fail-closed.
    denied = capability.enforce(tool_name, is_registered)
    if denied:
        return PolicyDecision("deny", denied, "capability.enforce")

    level = capability.level_of(tool_name)
    trust = set(trajectory_snapshot()["trust"])
    # Untrusted/retrieved content may inform analysis but cannot directly drive an
    # execute-level state mutation in the same trajectory. Proposals are safe
    # because their existing path is already human-approved before activation.
    if level in PRODUCTION_LEVELS and trust.intersection(UNTRUSTED):
        from .tool_provenance import ARTIFACT_TOOLS,verified_binding
        if tool_name in ARTIFACT_TOOLS and verified_binding(tool_name,arguments):
            return PolicyDecision('allow','verified_artifact_dependencies','arguments.evidence_binding')
        return PolicyDecision(
            "deny",
            "untrusted_evidence_cannot_drive_execute",
            "trajectory.untrusted_to_side_effect",
        )
    return PolicyDecision("allow", "policy_allow", "default_allow")


def authorize(tool_name: str, arguments: Dict[str, Any], is_registered: bool) -> str:
    envelope = _envelope(tool_name, arguments)
    decision = decide(tool_name, arguments, is_registered)
    _append_audit(envelope, decision, "pre_tool")
    if decision.outcome != "allow":
        return "policy %s: %s" % (decision.outcome, decision.reason_code)
    return ""


def record_result(tool_name: str, arguments: Dict[str, Any], result: Any) -> None:
    state = _trajectory.get()
    if state is None:
        reset_trajectory()
        state = _trajectory.get()
    state = copy.deepcopy(state)
    _trajectory.set(state)
    trust = SOURCE_TRUST.get(tool_name)
    if trust and trust not in state["trust"]:
        state["trust"].append(trust)
    state["tools"].append(tool_name)
    from .tool_provenance import record
    record(tool_name,arguments,result,state,_scope_fields(),trust)
    envelope = _envelope(tool_name, arguments)
    decision = PolicyDecision("allow", "tool_completed", "post_tool")
    _append_audit(envelope, decision, "post_tool", _digest(result))


def verify_audit_chain(path=None) -> Dict[str, Any]:
    path = path or (agent_audit_dir() / "governance_audit.jsonl")
    if not path.exists():
        return {"ok": True, "records": 0, "error_index": None}
    previous = ""
    count = 0
    for idx, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            return {"ok": False, "records": count, "error_index": idx, "reason": "invalid_json"}
        claimed = rec.pop("record_hash", "")
        if rec.get("previous_hash", "") != previous or _digest(rec) != claimed:
            return {"ok": False, "records": count, "error_index": idx, "reason": "hash_mismatch"}
        previous = claimed
        count += 1
    return {"ok": True, "records": count, "error_index": None, "head": previous}


def record_failure(tool_name, arguments, reason):
    _append_audit(_envelope(tool_name, arguments),
                  PolicyDecision('deny', reason, 'tool_failed'), 'post_tool')


def record_effective_arguments(tool_name, arguments):
    _append_audit(_envelope(tool_name, arguments),
                  PolicyDecision('allow', 'effective_arguments', 'tool_contract'), 'effective_args')
