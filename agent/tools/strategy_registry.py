# -*- coding: utf-8 -*-
"""策略注册表:策略版本的登记/校验/晋升/回滚(与模型登记簿同级的治理面)。

策略 = 规则集 + 阈值覆盖 + 特征/模型依赖 的版本化声明。状态机:
  draft --(校验门禁)--> validated --(自动)--> shadow --(人审批)--> active
  active --(审批+audit)--> rollback | deprecated(被同名新 active 顶替)

铁律:
  - 同名同版本覆盖禁止(版本不可变,修改 = 新版本);
  - 未通过 strategy_validate 不得离开 draft;
  - shadow -> active 必须人审批(approval_id 进记录);
  - 同名策略同时只有一个 active(新上线旧自动 deprecated);
  - Agent 不能直接修改 active 策略 —— 变更只能经"新版本 -> 审批"路径;
  - 每个版本记录 dataset_fingerprint,回放口径有据。

策略是元数据(数据/策略文件下的 strategy_registry.json,gitignored);
真正的阈值生效仍由 policy 版本表 + engine 适配器负责,本注册表不参与
判定,只治理"哪个策略版本处于什么状态"。
"""
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from . import tool
from .datasource import data_dir, pending_actions_path
from .dataset import dataset_fingerprint
from .featurelib import FEATURE_CATALOG
from .policy import DEFAULTS, SWITCH_KEYS
from .rules import RULE_COUNT

REGISTRY_FILE = "strategy_registry.json"

STATES = ("draft", "validated", "shadow", "active", "deprecated", "rollback")
_KNOWN_RULES = frozenset("R%03d" % i for i in range(1, RULE_COUNT + 1))
_FEATURE_KEYS = frozenset(c["key"] for c in FEATURE_CATALOG)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _path():
    return data_dir() / REGISTRY_FILE


def _load() -> List[Dict]:
    p = _path()
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else []


def _save(items: List[Dict]) -> None:
    _path().write_text(json.dumps(items, ensure_ascii=False, indent=1),
                       encoding="utf-8")


def _find(items: List[Dict], name: str, version: str) -> Optional[Dict]:
    for s in items:
        if s["strategy_name"] == name and s["version"] == version:
            return s
    return None


def _pending() -> List[Dict]:
    p = pending_actions_path()
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else []


def _save_pending(items: List[Dict]) -> None:
    pending_actions_path().write_text(
        json.dumps(items, ensure_ascii=False, indent=1), encoding="utf-8")


def _submit_pending(entry: Dict) -> int:
    pending = _pending()
    action_id = max((a["action_id"] for a in pending), default=0) + 1
    pending.append({"action_id": action_id, **entry})
    _save_pending(pending)
    return action_id


def validate_strategy(entry: Dict) -> Dict:
    """校验门禁:规则/阈值键/特征依赖/模型依赖四类检查,返回问题清单。"""
    problems = []
    rules = entry.get("rules") or []
    unknown_rules = [r for r in rules if r not in _KNOWN_RULES]
    if unknown_rules:
        problems.append("未知规则: %s(可用 %s)" % (unknown_rules, sorted(_KNOWN_RULES)))
    thr = entry.get("thresholds") or {}
    unknown_keys = [k for k in thr if k not in DEFAULTS]
    if unknown_keys:
        problems.append("未知阈值参数: %s" % unknown_keys)
    for k, v in thr.items():
        if k in SWITCH_KEYS and v not in (0, 1):
            problems.append("开关键 %s 只接受 0/1,收到 %r" % (k, v))
        elif not isinstance(v, (int, float)) or isinstance(v, bool):
            problems.append("阈值 %s 必须为数值,收到 %r" % (k, v))
    fdep = entry.get("feature_dependencies") or []
    unknown_f = [f for f in fdep if f not in _FEATURE_KEYS]
    if unknown_f:
        problems.append("未知特征依赖: %s" % unknown_f)
    mdep = entry.get("model_dependencies") or []
    if mdep:
        items = _load_model_registry()
        known = {(m["name"], m["version"]) for m in items}
        for dep in mdep:
            if ":" not in dep:
                problems.append("模型依赖格式须为 name:version,收到 %r" % dep)
                continue
            name, ver = dep.rsplit(":", 1)
            if (name, ver) not in known:
                problems.append("模型依赖未登记: %s" % dep)
    return {"valid": not problems, "problems": problems}


def _load_model_registry() -> List[Dict]:
    p = data_dir() / "model_registry.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else []


@tool(
    name="strategy_register",
    description=(
        "登记一个策略版本(状态 draft):规则集 + 阈值覆盖 + 特征/模型依赖。"
        "同名同版本禁止覆盖(修改 = 新版本)。阈值键必须是 policy 已知参数,"
        "模型依赖须已登记(model_registry)。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "strategy_name": {"type": "string", "description": "策略名"},
            "version": {"type": "string", "description": "版本号"},
            "rules": {"type": "array", "items": {"type": "string"},
                      "description": "启用的规则 id,如 [\"R001\",\"R002\"]"},
            "thresholds": {"type": "object",
                           "description": "阈值覆盖,如 {\"r002_max_gap_seconds\": 15}"},
            "feature_dependencies": {"type": "array", "items": {"type": "string"},
                                     "description": "依赖的特征键(见 feature_catalog)"},
            "model_dependencies": {"type": "array", "items": {"type": "string"},
                                   "description": "依赖的模型 \"name:version\""},
            "note": {"type": "string", "description": "策略意图/背景说明"},
        },
        "required": ["strategy_name", "version"],
    },
)
def strategy_register(strategy_name: str, version: str, rules: List[str] = None,
                      thresholds: Dict = None, feature_dependencies: List[str] = None,
                      model_dependencies: List[str] = None, note: str = ""):
    items = _load()
    if _find(items, strategy_name, version):
        return {"status": "already_registered",
                "strategy_name": strategy_name, "version": version}
    entry = {
        "strategy_name": strategy_name,
        "version": version,
        "rules": rules or [],
        "thresholds": thresholds or {},
        "feature_dependencies": feature_dependencies or [],
        "model_dependencies": model_dependencies or [],
        "effective_from": None,
        "effective_to": None,
        "status": "draft",
        "created_by": "agent",
        "approved_by": None,
        "approval_id": None,
        "deployed_at": None,
        "retired_at": None,
        "created_at": _now_iso(),
        "dataset_fingerprint": dataset_fingerprint(),
        "note": note,
    }
    items.append(entry)
    _save(items)
    return {"status": "registered", "entry": entry}


@tool(
    name="strategy_validate",
    description=(
        "校验策略版本:规则 id/阈值键与取值/特征依赖/模型依赖四类门禁。"
        "返回问题清单;valid=true 是离开 draft 的前提。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "strategy_name": {"type": "string", "description": "策略名"},
            "version": {"type": "string", "description": "版本号"},
        },
        "required": ["strategy_name", "version"],
    },
)
def strategy_validate(strategy_name: str, version: str):
    entry = _find(_load(), strategy_name, version)
    if entry is None:
        return {"error": "策略未登记: %s %s" % (strategy_name, version)}
    return {"strategy_name": strategy_name, "version": version,
            **validate_strategy(entry)}


@tool(
    name="strategy_list",
    description=(
        "列出策略版本:状态/规则/阈值覆盖/依赖/指纹/审批信息。"
        "name 可空=全部。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "strategy_name": {"type": "string", "description": "策略名(可空)"},
        },
    },
)
def strategy_list(strategy_name: str = ""):
    items = _load()
    if strategy_name:
        items = [s for s in items if s["strategy_name"] == strategy_name]
    active = [s["strategy_name"] + " " + s["version"] for s in items
              if s["status"] == "active"]
    return {"count": len(items), "strategies": items, "active": active}


@tool(
    name="strategy_diff",
    description=(
        "对比同一策略的两个版本:阈值覆盖差异 + 规则集差异 + 依赖差异。"
        "策略演进审计用。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "strategy_name": {"type": "string", "description": "策略名"},
            "version_a": {"type": "string", "description": "旧版本号"},
            "version_b": {"type": "string", "description": "新版本号"},
        },
        "required": ["strategy_name", "version_a", "version_b"],
    },
)
def strategy_diff(strategy_name: str, version_a: str, version_b: str):
    items = _load()
    a = _find(items, strategy_name, version_a)
    b = _find(items, strategy_name, version_b)
    if a is None or b is None:
        return {"error": "版本不存在: %s %s/%s" % (strategy_name, version_a, version_b)}
    thr_keys = sorted(set(a["thresholds"]) | set(b["thresholds"]))
    thr_diff = []
    for k in thr_keys:
        va, vb = a["thresholds"].get(k), b["thresholds"].get(k)
        if va != vb:
            thr_diff.append({"param": k, "a": va, "b": vb})
    return {
        "strategy_name": strategy_name,
        "version_a": version_a, "version_b": version_b,
        "threshold_diff": thr_diff,
        "rules_a": a["rules"], "rules_b": b["rules"],
        "feature_deps_a": a["feature_dependencies"],
        "feature_deps_b": b["feature_dependencies"],
        "model_deps_a": a["model_dependencies"],
        "model_deps_b": b["model_dependencies"],
    }


@tool(
    name="strategy_promote",
    description=(
        "策略状态转移:draft->validated(必须过校验门禁)、validated->shadow"
        " 自动、shadow->active 必须人审批(提交待审批,批准后同名旧 active"
        " 自动 deprecated)。未验证策略禁止离开 draft。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "strategy_name": {"type": "string", "description": "策略名"},
            "version": {"type": "string", "description": "版本号"},
            "to": {"type": "string", "enum": ["validated", "shadow", "active"],
                   "description": "目标状态"},
            "reason": {"type": "string", "description": "晋升理由(进审批与审计)"},
        },
        "required": ["strategy_name", "version", "to"],
    },
)
def strategy_promote(strategy_name: str, version: str, to: str, reason: str = ""):
    items = _load()
    entry = _find(items, strategy_name, version)
    if entry is None:
        return {"error": "策略未登记: %s %s" % (strategy_name, version)}
    cur = entry["status"]
    allowed = {"draft": ("validated",), "validated": ("shadow",),
               "shadow": ("active",)}
    if to not in allowed.get(cur, ()):
        return {"error": "非法转移 %s -> %s(允许: %s)"
                         % (cur, to, allowed.get(cur, ()) or "无")}
    if to == "validated":
        vr = validate_strategy(entry)
        if not vr["valid"]:
            return {"error": "校验门禁未过: %s" % "; ".join(vr["problems"])}
        entry["status"] = "validated"
        _save(items)
        return {"status": "promoted", "to": "validated"}
    if to == "shadow":
        entry["status"] = "shadow"
        _save(items)
        return {"status": "promoted", "to": "shadow", "note": "shadow 观察期"}
    aid = _submit_pending({
        "kind": "strategy_promote", "strategy_name": strategy_name,
        "version": version, "reason": reason, "requested_at": _now_iso(),
    })
    return {"status": "pending_confirmation", "action_id": aid,
            "note": "已提交待审批,批准后 active(同名旧 active 自动 deprecated)"}


def apply_active(action: Dict, decided_by: str) -> Dict:
    """actions.decide 批准后:同名旧 active 退役,新版本上线。"""
    items = _load()
    entry = _find(items, action["strategy_name"], action["version"])
    if entry is None:
        raise ValueError("策略未登记: %s %s"
                         % (action["strategy_name"], action["version"]))
    if entry["status"] != "shadow":
        raise ValueError("状态机拒绝: %s 当前为 %s,非 shadow"
                         % (entry["strategy_name"], entry["status"]))
    for s in items:
        if s["strategy_name"] == entry["strategy_name"] and s["status"] == "active":
            s["status"] = "deprecated"
            s["retired_at"] = _now_iso()
            s["note"] = (s.get("note", "") + ";被 %s 顶替" % entry["version"]).strip(";")
    entry["status"] = "active"
    entry["approval_id"] = str(action["action_id"])
    entry["approved_by"] = decided_by
    entry["deployed_at"] = _now_iso()
    _save(items)
    return {"strategy_name": entry["strategy_name"], "version": entry["version"],
            "status": "active"}


@tool(
    name="strategy_rollback",
    description=(
        "提交 active 策略回滚申请(走审批,批准后状态置 rollback 并写审计)。"
        "只允许对 active 版本回滚。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "strategy_name": {"type": "string", "description": "策略名"},
            "version": {"type": "string", "description": "版本号"},
            "reason": {"type": "string", "description": "回滚原因(进审批与审计)"},
        },
        "required": ["strategy_name", "version", "reason"],
    },
)
def strategy_rollback(strategy_name: str, version: str, reason: str = ""):
    items = _load()
    entry = _find(items, strategy_name, version)
    if entry is None:
        return {"error": "策略未登记: %s %s" % (strategy_name, version)}
    if entry["status"] != "active":
        return {"error": "非法回滚: %s 状态为 %s,只有 active 可回滚"
                         % (strategy_name, entry["status"])}
    aid = _submit_pending({
        "kind": "strategy_rollback", "strategy_name": strategy_name,
        "version": version, "reason": reason, "requested_at": _now_iso(),
    })
    return {"status": "pending_confirmation", "action_id": aid,
            "note": "已提交待审批,批准后回滚并写审计"}


def apply_strategy_rollback(action: Dict, decided_by: str) -> Dict:
    items = _load()
    entry = _find(items, action["strategy_name"], action["version"])
    if entry is None:
        raise ValueError("策略未登记: %s %s"
                         % (action["strategy_name"], action["version"]))
    if entry["status"] != "active":
        raise ValueError("非法回滚: %s 状态为 %s"
                         % (entry["strategy_name"], entry["status"]))
    entry["status"] = "rollback"
    entry["retired_at"] = _now_iso()
    entry["approval_id"] = str(action["action_id"])
    entry["approved_by"] = decided_by
    _save(items)
    return {"strategy_name": entry["strategy_name"], "version": entry["version"],
            "status": "rollback"}


# ---------------------------------------------------------------------------
# 策略回放 / 影子演练(反事实):历史事件在"候选策略阈值"下重跑一遍,
# 与当前策略对比。铁律:what-if != 生产决策 —— 覆盖只在本函数内生效并
# 必然恢复,不写 pending/audit/mismatch 队列,不触碰策略与名单。
# ---------------------------------------------------------------------------

def _replay_against(entry: Dict, uids: List[str]) -> Dict:
    """在 entry 的阈值覆盖下重放全部事件,返回与当前策略的对比。"""
    from . import policy
    from .backtest import account_verdicts
    from .datasource import load_events, load_labels

    events = load_events()
    labels = load_labels()
    target = uids or sorted(labels.keys())
    prev = policy.set_overrides(entry["thresholds"])
    try:
        new_v = account_verdicts(target, events, use_current_policy=True)
    finally:
        policy.restore_overrides(prev)
    base_v = account_verdicts(target, events, use_current_policy=True)

    order_sum: Dict[str, float] = {}
    for e in events:
        if e["type"] == "order" and e.get("amount") is not None and e["uid"] in target:
            order_sum[e["uid"]] = order_sum.get(e["uid"], 0.0) + e["amount"]

    def flagged(v: Dict[str, Dict]) -> set:
        return {u for u, x in v.items() if x["predicted"] in ("review", "reject")}

    def fp_fn(v: Dict[str, Dict]):
        f = flagged(v)
        fp = sum(1 for u in f if labels.get(u, {}).get("label") == "normal")
        fn = sum(1 for u in target
                 if u not in f and labels.get(u, {}).get("label") == "fraud")
        return fp, fn

    base_flag, new_flag = flagged(base_v), flagged(new_v)
    fp_base, fn_base = fp_fn(base_v)
    fp_new, fn_new = fp_fn(new_v)
    changes = [{"uid": u, "old_action": base_v[u]["predicted"],
                "new_action": new_v[u]["predicted"]}
               for u in target if base_v[u]["predicted"] != new_v[u]["predicted"]]
    cost_delta = (sum(order_sum.get(u, 0.0) for u in new_flag - base_flag)
                  - sum(order_sum.get(u, 0.0) for u in base_flag - new_flag))
    return {
        "what_if": True,
        "note": "反事实回放:what-if != 生产决策;未写 pending/audit/mismatch/策略",
        "compared": len(target),
        "changed_count": len(changes),
        "change_rate": round(len(changes) / len(target), 4) if target else 0.0,
        "false_positive_delta": fp_new - fp_base,
        "false_negative_delta": fn_new - fn_base,
        "cost_delta": round(cost_delta, 2),
        "changes": changes[:20],
        "dataset_fingerprint": entry.get("dataset_fingerprint"),
        "thresholds_used": entry["thresholds"],
    }


def _require_replayable(name: str, version: str) -> Dict:
    """取可回放的策略(validated/shadow/active),draft 拒绝。"""
    entry = _find(_load(), name, version)
    if entry is None:
        return {"error": "策略未登记: %s %s" % (name, version)}
    if entry["status"] == "draft":
        return {"error": "draft 未过校验门禁,不可回放(先 strategy_validate)"}
    return entry


@tool(
    name="strategy_replay",
    description=(
        "反事实回放:把历史事件在候选策略版本的阈值覆盖下重跑,与当前策略"
        "对比(改变数/改变率/误伤增量/漏放增量/成本增量)。明确:what-if 不"
        "等于生产决策,不写 pending/audit/mismatch/策略。可传 uids 限定账号"
        "范围;model_version 仅作血缘记录(骨架中模型未接入判定)。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "strategy_name": {"type": "string", "description": "策略名"},
            "version": {"type": "string", "description": "版本号"},
            "uids": {"type": "array", "items": {"type": "string"},
                     "description": "限定账号(可空=全部已标注账号)"},
            "model_version": {"type": "string",
                              "description": "模型血缘记录 \"name:version\"(可空)"},
        },
        "required": ["strategy_name", "version"],
    },
)
def strategy_replay(strategy_name: str, version: str,
                    uids: List[str] = None, model_version: str = ""):
    entry = _require_replayable(strategy_name, version)
    if "error" in entry:
        return entry
    if model_version:
        items = _load_model_registry()
        if ":" not in model_version or tuple(model_version.rsplit(":", 1)) \
                not in {(m["name"], m["version"]) for m in items}:
            return {"error": "model_version 未登记: %s" % model_version}
    out = _replay_against(entry, list(uids) if uids else [])
    out["strategy"] = "%s %s" % (strategy_name, version)
    out["model_version"] = model_version or None
    return out


@tool(
    name="strategy_shadow",
    description=(
        "影子演练:同 strategy_replay(反事实对比),并把结果落盘到 out/shadow/"
        "(带指纹与时间戳),返回路径与摘要 —— 供离线评审与归档,绝不进生产。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "strategy_name": {"type": "string", "description": "策略名"},
            "version": {"type": "string", "description": "版本号"},
            "uids": {"type": "array", "items": {"type": "string"},
                     "description": "限定账号(可空)"},
            "model_version": {"type": "string",
                              "description": "模型血缘记录(可空)"},
        },
        "required": ["strategy_name", "version"],
    },
)
def strategy_shadow(strategy_name: str, version: str,
                    uids: List[str] = None, model_version: str = ""):
    entry = _require_replayable(strategy_name, version)
    if "error" in entry:
        return entry
    out = _replay_against(entry, list(uids) if uids else [])
    out["strategy"] = "%s %s" % (strategy_name, version)
    out["model_version"] = model_version or None
    out["created_at"] = _now_iso()
    from pathlib import Path
    shadow_dir = (Path(__file__).resolve().parent.parent.parent
                  / "out" / "shadow")
    shadow_dir.mkdir(parents=True, exist_ok=True)
    path = shadow_dir / ("%s-%s.json" % (strategy_name, version))
    path.write_text(json.dumps(out, ensure_ascii=False, indent=1),
                    encoding="utf-8")
    return {"shadow_path": str(path), **{k: out[k] for k in
            ("what_if", "changed_count", "change_rate", "cost_delta",
             "compared", "created_at")}}
