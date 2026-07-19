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
from datetime import datetime, timezone
from typing import Dict, List, Optional

from . import tool
from . import policy
from .datasource import audit_log_path, blacklist_path, load_blacklist, pending_actions_path

VALID_DIMENSIONS = ("uid", "ip", "device_id")
VALID_LISTS = ("black", "gray")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_pending() -> List[Dict]:
    p = pending_actions_path()
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else []


def _save_pending(items: List[Dict]) -> None:
    pending_actions_path().write_text(
        json.dumps(items, ensure_ascii=False, indent=1), encoding="utf-8")


@tool(
    name="blacklist_add",
    description=(
        "提交一条名单写入申请(black=黑名单 / gray=灰名单)。注意:此操作不会"
        "立即生效 —— 申请进入待审批队列,需研究员在 CLI 执行 /approve 确认后"
        "才写入名单库。reason 必须写清证据(命中哪些规则/信号、关键数值),"
        "这会进入审计日志。同一值已在名单或已在队列时返回现状。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "dimension": {"type": "string", "enum": list(VALID_DIMENSIONS)},
            "value": {"type": "string", "description": "要拉入名单的值"},
            "list": {"type": "string", "enum": list(VALID_LISTS),
                     "description": "black(确凿证据)或 gray(嫌疑,需持续观察)"},
            "reason": {"type": "string", "description": "证据说明,将写入名单与审计日志"},
        },
        "required": ["dimension", "value", "list", "reason"],
    },
)
def blacklist_add(dimension: str, value: str, reason: str, **kw):
    target_list = kw.get("list")
    if dimension not in VALID_DIMENSIONS or target_list not in VALID_LISTS:
        return {"error": "dimension 必须是 %s 之一,list 必须是 %s 之一" % (VALID_DIMENSIONS, VALID_LISTS)}
    existing = [r for r in load_blacklist() if r["dimension"] == dimension and r["value"] == value]
    if existing:
        return {"status": "already_listed", "records": existing}
    pending = _load_pending()
    # 防重只在同 kind 内比对:threshold_change 条目没有 dimension/value 字段
    dup = [a for a in pending if a.get("kind", "blacklist_add") == "blacklist_add"
           and a["dimension"] == dimension and a["value"] == value]
    if dup:
        return {"status": "already_pending", "action_id": dup[0]["action_id"]}
    action_id = max((a["action_id"] for a in pending), default=0) + 1
    pending.append({
        "action_id": action_id,
        "kind": "blacklist_add",
        "dimension": dimension,
        "value": value,
        "list": target_list,
        "reason": reason,
        "requested_at": _now_iso(),
    })
    _save_pending(pending)
    return {
        "status": "pending_confirmation",
        "action_id": action_id,
        "note": "已提交待审批,需研究员在 CLI 执行 /approve %d 后生效" % action_id,
    }


@tool(
    name="threshold_propose",
    description=(
        "提交阈值变更申请(不会立即生效):进入待审批队列,需研究员在 CLI 执行 "
        "/approve 后才写入策略版本表。values 键同 rule_backtest 的 overrides 及 "
        "monitor/自身基线阈值;单参数变幅超过 ±50% 会被限速拒绝(需分步提案)。"
        "提交前必须先用 shadow_backtest 验证影响,reason 里写清指标证据。"
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
    # 开关型参数(0/1)不适用比例限速:1->0 的变幅是 100%,按比例永远提不了案
    too_big = ["%s: %s -> %s" % (k, current[k], v) for k, v in values.items()
               if not {current[k], v} <= {0, 1}
               and current[k] and abs(v - current[k]) / abs(current[k]) > policy.MAX_CHANGE_RATIO]
    if too_big:
        return {"status": "rejected_rate_limit",
                "detail": too_big,
                "note": "单次变幅限速 ±%d%%(防被极端数据/被养过的基线一次带飞);"
                        "确需大改请分步提案并逐步验证" % int(policy.MAX_CHANGE_RATIO * 100)}
    pending = _load_pending()
    dup = [a for a in pending if a.get("kind") == "threshold_change"
           and set(a["values"]) & set(values)]
    if dup:
        return {"status": "already_pending", "action_id": dup[0]["action_id"]}
    action_id = max((a["action_id"] for a in pending), default=0) + 1
    pending.append({
        "action_id": action_id,
        "kind": "threshold_change",
        "values": values,
        "current": {k: current[k] for k in values},
        "reason": reason,
        "requested_at": _now_iso(),
    })
    _save_pending(pending)
    return {"status": "pending_confirmation", "action_id": action_id,
            "note": "已提交待审批,需研究员在 CLI 执行 /approve %d 后生效" % action_id}


# ---------------------------------------------------------------------------
# 以下为 CLI 专用(人工审批),不注册为工具,模型不可调用。
# ---------------------------------------------------------------------------

def list_pending() -> List[Dict]:
    return _load_pending()


def decide(action_id: int, approve: bool) -> Optional[Dict]:
    """审批一条申请:按 kind 分派落盘(名单库 / 策略版本表),统一记审计。
    返回该申请,查无返回 None。"""
    pending = _load_pending()
    matched = [a for a in pending if a["action_id"] == action_id]
    if not matched:
        return None
    action = matched[0]
    kind = action.get("kind", "blacklist_add")
    _save_pending([a for a in pending if a["action_id"] != action_id])
    applied_version = None
    applied_detail = None
    if approve:
        if kind == "threshold_change":
            applied_version = policy.apply_change(action)["version"]
        elif kind == "appeal_resolve":
            from .feedback import apply_appeal_decision  # 惰性:防导入环
            applied_detail = apply_appeal_decision(action)
        else:
            records = load_blacklist()
            records.append({
                "dimension": action["dimension"],
                "value": action["value"],
                "list": action["list"],
                "reason": action["reason"],
                "added_at": _now_iso()[:10],
                "source": "agent_proposed+human_approved",
            })
            blacklist_path().write_text(
                json.dumps(records, ensure_ascii=False, indent=1), encoding="utf-8")
    with open(audit_log_path(), "a", encoding="utf-8") as f:
        f.write(json.dumps({
            "ts": _now_iso(),
            "decision": "approve" if approve else "deny",
            "kind": kind,
            "applied_policy_version": applied_version,
            **({"applied_detail": applied_detail} if applied_detail else {}),
            "action": action,
        }, ensure_ascii=False) + "\n")
    return action
