# -*- coding: utf-8 -*-
"""处置执行工具:名单写入 + 阈值变更,统一走两阶段审批。

写操作的权限边界(为什么这样设计):
- agent 只有"提交"权:blacklist_add / threshold_propose 只把申请写进
  pending 队列(kind 区分类型),不落名单、不改策略。
- 审批权在人:研究员在 CLI 用 /pending 查看、/approve <id> 或 /deny <id>
  决定;approve/deny 不是注册工具,模型无法调用 —— 这不是提示词约束,
  是能力上不给。
- 全程留痕:每次审批(通过或驳回)追加一行审计日志(jsonl),记录时间、
  决定、完整申请内容,事后可回溯"这条名单/阈值是谁依据什么改的"。
- 幂等防重:已在名单/已在队列的申请直接返回现状,不重复排队。
- 阈值提案额外限速(policy.MAX_CHANGE_RATIO):单参数变幅超 ±50% 直接拒,
  防自动校准被极端数据(或被"养"过的基线)一次带飞。
"""
import json
import os
import getpass
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Optional

from . import tool
from . import policy
from .blacklist import VALID_LISTS, active_records
from .datasource import (
    appeals_path, append_jsonl, atomic_write_json, atomic_write_text,
    audit_log_path, blacklist_path, data_dir, file_lock, invalidate_cache,
    labels_path, load_blacklist, pending_actions_path, postmortems_path,
    state_write_lock, thresholds_path,
)

VALID_DIMENSIONS = ("uid", "ip", "device_id")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_pending() -> List[Dict]:
    p = pending_actions_path()
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else []


def _save_pending(items: List[Dict]) -> None:
    atomic_write_json(pending_actions_path(), items)


def mutate_pending(fn):
    """在 pending 文件锁内读-改-写。fn(items) 就地修改并返回结果。"""
    p = pending_actions_path()
    with file_lock(p):
        items = json.loads(p.read_text(encoding="utf-8")) if p.exists() else []
        previous = {a["action_id"] for a in items}
        counter_path = data_dir() / "proposal_sequence.json"
        counter = json.loads(counter_path.read_text()) if counter_path.exists() else 0
        counter = max(counter, max(previous, default=0))
        # Import historical IDs once; never recycle completed proposals.
        if not counter_path.exists() and audit_log_path().exists():
            for line in audit_log_path().read_text().splitlines():
                historical = json.loads(line).get("action", {}).get("action_id", 0)
                counter = max(counter, historical)
        result = fn(items)
        for item in items:
            if item["action_id"] in previous:
                continue
            old_id = item["action_id"]
            counter += 1
            item["action_id"] = counter
            item["revision"] = 1
            item["proposal_digest"] = _proposal_digest(item)
            if type(result) is int and result == old_id:
                result = counter
            if isinstance(result, dict) and result.get("action_id") == old_id:
                result["action_id"] = counter
                if "note" in result:
                    result["note"] = result["note"].replace("/approve %d" % old_id, "/approve %d" % counter)
        # Advance before pending write: a failed write burns an ID safely.
        atomic_write_json(counter_path, counter)
        atomic_write_json(p, items)
        return result


def _proposal_digest(action):
    body = {k: v for k, v in action.items() if k != "proposal_digest"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False,
                                     allow_nan=False).encode()).hexdigest()


def _limit_violations(values: Dict, current: Dict) -> List[str]:
    """逐参数校验变更幅度,返回违规说明列表(空=全部通过)。
    - 开关键:取值只允许 0/1,其余(含 0.5 这类)一律拒。
    - 枚举键:只接受 ENUM_KEYS 声明的字面量,不走 ±50%(worst→vote 不是变幅)。
    - 数值键:按 ±MAX_CHANGE_RATIO 限速;现值为 0 时比例无意义,任何非零变更
      都是无穷变幅,一律拒(需先小步离开 0)—— 之前 `and current[k]` 会在
      现值 0 时短路跳过整个检查,让被某版本置 0 的参数(如 r006_reject_rooted=0)
      可无限幅提案。"""
    bad = []
    for k, v in values.items():
        if k in policy.SWITCH_KEYS:
            if v not in (0, 1):
                bad.append("%s: 开关键只接受 0/1,收到 %s" % (k, v))
            continue
        if k in policy.ENUM_KEYS:
            allowed = policy.ENUM_KEYS[k]
            if v not in allowed:
                bad.append("%s: 枚举键只接受 %s,收到 %s" % (k, "/".join(allowed), v))
            continue
        cur = current[k]
        if cur == 0:
            if v != 0:
                bad.append("%s: %s -> %s(现值 0,任何非零变更均超限速,请分步)" % (k, cur, v))
        elif abs(v - cur) / abs(cur) > policy.MAX_CHANGE_RATIO:
            bad.append("%s: %s -> %s" % (k, cur, v))
    return bad


@tool(
    name="blacklist_add",
    description=(
        "提交名单写入申请(black/gray/white),进待审批队列,需 /approve 才生效。"
        "仅当研究员明确要求加名单/升黑/加白时才调用;调查、日报、团伙排查"
        "只给文字建议。未点名或要求立即生效/不用审批时运行时硬拒,不进队列。"
        "reason 写清证据,进审计日志。"
        "white 必须带 scope/owner/expires_days(1..30);gray 未带时按默认观察期提交。"
        "同值同色已在名单/队列返回现状;不同色允许提交(灰升黑、黑值申诉加白)。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "dimension": {"type": "string", "enum": list(VALID_DIMENSIONS)},
            "value": {"type": "string", "description": "要拉入名单的值"},
            "list": {"type": "string", "enum": list(VALID_LISTS),
                     "description": "black(确凿证据)/ gray(嫌疑观察)/ white(误伤抑制)"},
            "reason": {"type": "string", "description": "证据说明,将写入名单与审计日志"},
            "scope": {"type": "string", "description": "白名单业务事件类型"},
            "owner": {"type": "string", "description": "白名单责任人"},
            "expires_days": {"type": "integer", "minimum": 1,
                             "description": "有效期天数;白名单必填,范围1..30"},
        },
        "required": ["dimension", "value", "list", "reason"],
    },
)
def blacklist_add(dimension: str, value: str, reason: str, expires_days: int = 0, **kw):
    target_list = kw.get("list")
    if dimension not in VALID_DIMENSIONS or target_list not in VALID_LISTS:
        return {"error": "dimension 必须是 %s 之一,list 必须是 %s 之一" % (VALID_DIMENSIONS, VALID_LISTS)}
    if target_list == "white":
        if (type(expires_days) is not int or not 1 <= expires_days <= 30
                or not str(kw.get("scope", "")).strip()
                or kw.get("scope") == "*"
                or not str(kw.get("owner", "")).strip() or not reason.strip()):
            return {"error": "white requires scope, owner, reason and expiry 1..30 days"}
    # 防重按(维度, 值, 同色)比对:不同色是合法诉求(灰升黑 / 黑值申诉加白),
    # 冲突裁决在规则引擎(黑白并存以黑为准)与人工审批,不在提交入口一刀切。
    # 只看未过期记录(active_records):过期记录在规则引擎里"视为不存在",
    # 若还挡新申请,过期后卷土重来的值就永远无法再次拉黑
    existing = active_records(dimension, value, lists=(target_list,), scope=kw.get("scope"))
    if existing:
        return {"status": "already_listed", "records": existing}

    def _add(pending):
        dup = [a for a in pending if a.get("kind", "blacklist_add") == "blacklist_add"
               and a["dimension"] == dimension and a["value"] == value
               and a.get("list") == target_list
               and a.get("scope") == kw.get("scope")]
        if dup:
            return {"status": "already_pending", "action_id": dup[0]["action_id"]}
        action_id = max((a["action_id"] for a in pending), default=0) + 1
        entry = {
            "action_id": action_id,
            "kind": "blacklist_add",
            "dimension": dimension,
            "value": value,
            "list": target_list,
            "reason": reason,
            "requested_at": _now_iso(),
        }
        if target_list == "white":
            entry.update(scope=kw["scope"], owner=kw["owner"])
        note = "已提交待审批,需研究员在 CLI 执行 /approve %d 后生效" % action_id
        if expires_days and expires_days > 0:
            entry["expires_days"] = int(expires_days)
        elif target_list == "gray":
            entry["expires_days"] = int(policy.active_policy()["graylist_observe_days"])
            note += ";灰名单未指定有效期,已按默认观察期 %d 天提交" % entry["expires_days"]
        pending.append(entry)
        return {"status": "pending_confirmation", "action_id": action_id, "note": note}

    return mutate_pending(_add)


@tool(
    name="blacklist_remove",
    description=(
        "提交名单移除申请(出灰/申诉纠错),进待审批队列,需 /approve 生效并记"
        "审计。reason 写清依据(graylist_review 结论、申诉工单号)。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "dimension": {"type": "string", "enum": list(VALID_DIMENSIONS)},
            "value": {"type": "string", "description": "要移出的值"},
            "list": {"type": "string", "enum": list(VALID_LISTS),
                     "description": "要移出的名单颜色"},
            "reason": {"type": "string", "description": "移除依据,进审计日志"},
        },
        "required": ["dimension", "value", "list", "reason"],
    },
)
def blacklist_remove(dimension: str, value: str, reason: str, **kw):
    target_list = kw.get("list")
    if dimension not in VALID_DIMENSIONS or target_list not in VALID_LISTS:
        return {"error": "dimension 必须是 %s 之一,list 必须是 %s 之一" % (VALID_DIMENSIONS, VALID_LISTS)}
    existing = [r for r in load_blacklist() if r["dimension"] == dimension
                and r["value"] == value and r["list"] == target_list]
    if not existing:
        return {"status": "not_listed", "note": "该值不在 %s 名单中,无需移除" % target_list}

    def _rm(pending):
        dup = [a for a in pending if a.get("kind") == "blacklist_remove"
               and a["dimension"] == dimension and a["value"] == value
               and a.get("list") == target_list]
        if dup:
            return {"status": "already_pending", "action_id": dup[0]["action_id"]}
        action_id = max((a["action_id"] for a in pending), default=0) + 1
        pending.append({
            "action_id": action_id,
            "kind": "blacklist_remove",
            "dimension": dimension,
            "value": value,
            "list": target_list,
            "reason": reason,
            "requested_at": _now_iso(),
        })
        return {"status": "pending_confirmation", "action_id": action_id,
                "note": "已提交待审批,需研究员在 CLI 执行 /approve %d 后移除" % action_id}

    return mutate_pending(_rm)


@tool(
    name="threshold_propose",
    description=(
        "提交阈值变更申请(不会立即生效):进入待审批队列,需研究员在 CLI 执行 "
        "/approve 后才写入策略版本表。用户要求立即生效/不用审批时不要调用。"
        "values 键同 rule_backtest 的 overrides 及 monitor/自身基线阈值;"
        "单参数变幅超过 ±50% 会被限速拒绝(需分步提案)。"
        "可回测键会在提交时强制跑影子回测,完整证据落成独立产物,"
        "pending 只绑 artifact_id+哈希;影子失败则拒提案。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "values": {"type": "object",
                       "description": "要变更的阈值,如 {\"r002_max_gap_seconds\": 15}"},
            "reason": {"type": "string",
                       "description": "变更依据(扫描/影子回测的指标证据),进入审计日志"},
        },
        "required": ["values", "reason"],
    },
)
def threshold_propose(values: Dict, reason: str):
    if not values:
        return {"error": "values 不能为空"}
    bad = [k for k in values if k not in policy.DEFAULTS]
    if bad:
        return {"error": "未知阈值参数: %s" % ", ".join(bad)}
    current = policy.active_policy()
    baseline = policy.baseline_digest()
    bad = _limit_violations(values, current)
    if bad:
        return {"status": "rejected_rate_limit",
                "detail": bad,
                "note": "开关键只接受 0/1;枚举键只接受声明字面量且不限速;"
                        "数值键单次变幅限速 ±%d%%(防被极端数据/"
                        "被养过的基线一次带飞),现值为 0 的键任何非零变更都超限,"
                        "确需大改请分步提案并逐步验证" % int(policy.MAX_CHANGE_RATIO * 100)}
    from .backtest import OVERRIDABLE, shadow_compare
    from .shadow_store import write_threshold_artifact
    shadow_keys = {k: v for k, v in values.items() if k in OVERRIDABLE}
    shadow_bind = None
    if shadow_keys:
        shadow = shadow_compare(shadow_keys)
        if "error" in shadow:
            return {"status": "rejected_shadow", "detail": shadow["error"],
                    "note": "可回测参数必须先完成影子回测"}
        shadow_bind = write_threshold_artifact(shadow_keys, shadow)

    def _prop(pending):
        dup = [a for a in pending if a.get("kind") == "threshold_change"
               and set(a["values"]) & set(values)]
        if dup:
            return {"status": "already_pending", "action_id": dup[0]["action_id"]}
        action_id = max((a["action_id"] for a in pending), default=0) + 1
        rec = {
            "action_id": action_id,
            "kind": "threshold_change",
            "values": values,
            "current": {k: current[k] for k in values},
            "baseline_digest": baseline,
            "reason": reason,
            "requested_at": _now_iso(),
        }
        if shadow_bind:
            rec["shadow"] = shadow_bind
        pending.append(rec)
        out = {"status": "pending_confirmation", "action_id": action_id,
               "note": "已提交待审批,需研究员在 CLI 执行 /approve %d 后生效" % action_id}
        if shadow_bind:
            out["artifact_id"] = shadow_bind.get("artifact_id")
        return out

    return mutate_pending(_prop)


# ---------------------------------------------------------------------------
# 以下为 CLI 专用(人工审批),不注册为工具,模型不可调用。
# ---------------------------------------------------------------------------

def list_pending() -> List[Dict]:
    return _load_pending()


def _write_blacklist(records: List[Dict]) -> None:
    """名单落盘:文件锁 + 原子替换。mkdir=False 让父目录缺失仍抛 OSError,
    审批失败时申请留队(eval 审批原子性钉依赖此语义)。"""
    path = blacklist_path()
    with file_lock(path, mkdir=False):
        atomic_write_json(path, records, mkdir=False)


def _approval_journal_path():
    return data_dir() / "approval_transaction.json"


def _approval_paths(action: Dict) -> List:
    """审批可能触及的文件；事务日志保存原文快照用于异常/崩溃恢复。"""
    paths = [pending_actions_path(), audit_log_path(),
             data_dir() / "audit_pending.jsonl"]
    kind = action.get("kind", "blacklist_add")
    if kind in ("blacklist_add", "blacklist_remove"):
        paths.append(blacklist_path())
    elif kind == "threshold_change":
        paths.append(thresholds_path())
    elif kind == "appeal_resolve":
        paths.extend([appeals_path(), blacklist_path(), labels_path(),
                      data_dir() / "label_lineage.jsonl", postmortems_path()])
    elif kind in ("model_promote", "model_rollback"):
        paths.append(data_dir() / "model_registry.json")
    elif kind in ("strategy_promote", "strategy_rollback"):
        paths.append(data_dir() / "strategy_registry.json")
    # 保持顺序且去重。
    return list(dict.fromkeys(paths))


def _snapshot_files(paths: List) -> Dict[str, Dict]:
    out = {}
    for path in paths:
        p = path
        out[str(p)] = {
            "exists": p.exists(),
            "content": p.read_text(encoding="utf-8") if p.exists() else "",
        }
    return out


def _restore_files(snapshots: Dict[str, Dict]) -> None:
    for raw_path, snap in snapshots.items():
        from pathlib import Path
        path = Path(raw_path)
        if snap.get("exists"):
            atomic_write_text(path, snap.get("content", ""))
        elif path.exists():
            path.unlink()
            invalidate_cache(path)


def _recover_approval_transaction_locked() -> bool:
    journal = _approval_journal_path()
    if not journal.exists():
        return False
    obj = json.loads(journal.read_text(encoding="utf-8"))
    if obj.get("status") != "committed":
        _restore_files(obj.get("snapshots") or {})
    journal.unlink(missing_ok=True)
    return True


def recover_approval_transaction() -> bool:
    """启动/下一次审批时恢复未提交事务；committed 残留只做清理。"""
    with state_write_lock():
        return _recover_approval_transaction_locked()


def decide(action_id: int, approve: bool, operator: Optional[str] = None) -> Optional[Dict]:
    """审批一条申请:按 kind 分派落盘(名单库 / 策略版本表),统一记审计。
    返回该申请,查无返回 None。
    审计身份:operator 参数 > FK_OPERATOR 环境变量 > 当前 OS 账号。
    不再用无法追溯主体的通用 "cli"；生产仍应由 SSO 注入 FK_OPERATOR。"""
    decided_by = (operator or os.environ.get("FK_OPERATOR")
                  or "os:%s" % getpass.getuser())
    path = pending_actions_path()

    def _apply(pending):
        matched = [a for a in pending if a["action_id"] == action_id]
        if not matched:
            return None
        action = matched[0]
        kind = action.get("kind", "blacklist_add")
        applied_version = None
        applied_detail = None
        # 先落盘、后出队:apply 抛异常时申请留在队列可重试。
        if approve:
            if (kind == "threshold_change" or "proposal_digest" in action) and action.get("proposal_digest") != _proposal_digest(action):
                raise ValueError("proposal digest mismatch; resubmit proposal")
            if os.environ.get("FK_ENV", "").lower() in ("prod", "production"):
                raise ValueError("production activation requires external release controller")
            if kind == "threshold_change":
                bind = action.get("shadow") or {}
                if bind.get("artifact_id") or bind.get("sha256"):
                    from .shadow_store import verify_threshold_artifact
                    body = verify_threshold_artifact(bind)
                    expected = {k: v for k, v in action["values"].items() if k in policy.OVERRIDABLE}
                    if body["overrides"] != expected:
                        raise ValueError("shadow overrides do not match approved values")
                else:
                    exp = bind.get("expires_at")
                    if exp and exp < _now_iso():
                        raise ValueError("影子证据已过期(%s),请重新提案" % exp)
                if any(k in policy.OVERRIDABLE for k in action["values"]) and not bind.get("artifact_id"):
                    raise ValueError("shadow artifact required")
                applied_version = policy.apply_change(action, decided_by)["version"]
            elif kind == "appeal_resolve":
                from .feedback import apply_appeal_decision  # 惰性:防导入环
                applied_detail = apply_appeal_decision(action)
            elif kind == "model_promote":
                from .model_registry import apply_champion_promote  # 惰性
                applied_detail = apply_champion_promote(action, decided_by)
            elif kind == "model_rollback":
                from .model_registry import apply_rollback  # 惰性
                applied_detail = apply_rollback(action, decided_by)
            elif kind == "strategy_promote":
                from .strategy_registry import apply_active  # 惰性
                applied_detail = apply_active(action, decided_by)
            elif kind == "strategy_rollback":
                from .strategy_registry import apply_strategy_rollback  # 惰性
                applied_detail = apply_strategy_rollback(action, decided_by)
            elif kind == "blacklist_remove":
                records = [r for r in load_blacklist()
                           if not (r["dimension"] == action["dimension"]
                                   and r["value"] == action["value"]
                                   and r["list"] == action["list"])]
                _write_blacklist(records)
            else:
                records = list(load_blacklist())
                rec = {
                    "dimension": action["dimension"],
                    "value": action["value"],
                    "list": action["list"],
                    "reason": action["reason"],
                    "added_at": _now_iso()[:10],
                    "source": "agent_proposed+human_approved",
                }
                if action["list"] == "white":
                    if not (action.get("scope") and action.get("owner") and action.get("reason")
                            and 1 <= action.get("expires_days", 0) <= 30):
                        raise ValueError("white requires scope/owner/reason/expiry")
                    rec.update(scope=action["scope"], owner=action["owner"])
                if action.get("expires_days"):
                    exp = datetime.now(timezone.utc).timestamp() + action["expires_days"] * 86400
                    rec["expires_at"] = datetime.fromtimestamp(
                        exp, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ" if action["list"] == "white" else "%Y-%m-%d")
                records.append(rec)
                _write_blacklist(records)
        leftover = [a for a in pending if a["action_id"] != action_id]
        pending[:] = leftover
        return {
            "action": action, "kind": kind,
            "applied_version": applied_version,
            "applied_detail": applied_detail,
        }

    with state_write_lock():
        _recover_approval_transaction_locked()
        with file_lock(path):
            pending = json.loads(path.read_text(encoding="utf-8")) if path.exists() else []
            matched = [a for a in pending if a["action_id"] == action_id]
            if not matched:
                return None
            journal = {
                "status": "prepared",
                "action_id": action_id,
                "approve": bool(approve),
                "operator": decided_by,
                "prepared_at": _now_iso(),
                "snapshots": _snapshot_files(_approval_paths(matched[0])),
            }
            atomic_write_json(_approval_journal_path(), journal)
            try:
                result = _apply(pending)
                atomic_write_json(path, pending)
                audit_rec = {
                    "ts": _now_iso(),
                    "decided_by": decided_by,
                    "decision": "approve" if approve else "deny",
                    "kind": result["kind"],
                    "applied_policy_version": result["applied_version"],
                    **({"applied_detail": result["applied_detail"]}
                       if result["applied_detail"] else {}),
                    "action": result["action"],
                }
                # 审计是提交条件，不再允许状态已生效而审计静默丢失。
                append_jsonl(audit_log_path(), audit_rec)
                journal["status"] = "committed"
                atomic_write_json(_approval_journal_path(), journal)
            except Exception:
                _restore_files(journal["snapshots"])
                _approval_journal_path().unlink(missing_ok=True)
                raise
            _approval_journal_path().unlink(missing_ok=True)
    if not approve:
        from .feedback_pipeline import record_override  # 惰性:否决回灌训练信号
        record_override({
            "kind": "proposal_denied",
            "action_kind": result["kind"],
            "action_id": result["action"].get("action_id"),
            "decided_by": decided_by,
            "reason": result["action"].get("reason", ""),
            "ts": _now_iso(),
        })
    return result["action"]
