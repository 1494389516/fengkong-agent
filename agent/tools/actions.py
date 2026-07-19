# -*- coding: utf-8 -*-
"""处置执行工具:名单写入,两阶段设计。

写操作的权限边界(为什么这样设计):
- agent 只有"提交"权:blacklist_add 只把申请写进 pending 队列,不落名单。
- 审批权在人:研究员在 CLI 用 /pending 查看、/approve <id> 或 /deny <id>
  决定;approve/deny 不是注册工具,模型无法调用 —— 这不是提示词约束,
  是能力上不给。
- 全程留痕:每次审批(通过或驳回)追加一行审计日志(jsonl),记录时间、
  决定、完整申请内容,事后可回溯"这条名单是谁依据什么加的"。
- 幂等防重:已在名单/已在队列的申请直接返回现状,不重复排队。
"""
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional

from . import tool
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
    dup = [a for a in pending if a["dimension"] == dimension and a["value"] == value]
    if dup:
        return {"status": "already_pending", "action_id": dup[0]["action_id"]}
    action_id = max((a["action_id"] for a in pending), default=0) + 1
    pending.append({
        "action_id": action_id,
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


# ---------------------------------------------------------------------------
# 以下为 CLI 专用(人工审批),不注册为工具,模型不可调用。
# ---------------------------------------------------------------------------

def list_pending() -> List[Dict]:
    return _load_pending()


def decide(action_id: int, approve: bool) -> Optional[Dict]:
    """审批一条申请。approve=True 写入名单库,False 仅记录驳回。返回该申请,查无返回 None。"""
    pending = _load_pending()
    matched = [a for a in pending if a["action_id"] == action_id]
    if not matched:
        return None
    action = matched[0]
    _save_pending([a for a in pending if a["action_id"] != action_id])
    if approve:
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
            "action": action,
        }, ensure_ascii=False) + "\n")
    return action
