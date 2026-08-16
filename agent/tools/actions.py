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
from datetime import datetime, timezone
from typing import Dict, List, Optional

from . import tool
from . import policy
from .blacklist import VALID_LISTS, active_records
from .datasource import audit_log_path, blacklist_path, load_blacklist, pending_actions_path

VALID_DIMENSIONS = ("uid", "ip", "device_id")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_pending() -> List[Dict]:
    p = pending_actions_path()
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else []


def _save_pending(items: List[Dict]) -> None:
    pending_actions_path().write_text(
        json.dumps(items, ensure_ascii=False, indent=1), encoding="utf-8")


def _limit_violations(values: Dict, current: Dict) -> List[str]:
    """逐参数校验变更幅度,返回违规说明列表(空=全部通过)。
    - 开关键:取值只允许 0/1,其余(含 0.5 这类)一律拒。
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
        "white 建议必带 expires_days;gray 未带时按默认观察期提交。"
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
            "expires_days": {"type": "integer", "minimum": 1,
                             "description": "可选:有效期天数,到期自动失效(白名单强烈建议携带)"},
        },
        "required": ["dimension", "value", "list", "reason"],
    },
)
def blacklist_add(dimension: str, value: str, reason: str, expires_days: int = 0, **kw):
    target_list = kw.get("list")
    if dimension not in VALID_DIMENSIONS or target_list not in VALID_LISTS:
        return {"error": "dimension 必须是 %s 之一,list 必须是 %s 之一" % (VALID_DIMENSIONS, VALID_LISTS)}
    # 防重按(维度, 值, 同色)比对:不同色是合法诉求(灰升黑 / 黑值申诉加白),
    # 冲突裁决在规则引擎(黑白并存以黑为准)与人工审批,不在提交入口一刀切。
    # 只看未过期记录(active_records):过期记录在规则引擎里"视为不存在",
    # 若还挡新申请,过期后卷土重来的值就永远无法再次拉黑
    existing = active_records(dimension, value, lists=(target_list,))
    if existing:
        return {"status": "already_listed", "records": existing}
    pending = _load_pending()
    dup = [a for a in pending if a.get("kind", "blacklist_add") == "blacklist_add"
           and a["dimension"] == dimension and a["value"] == value
           and a.get("list") == target_list]
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
    note = "已提交待审批,需研究员在 CLI 执行 /approve %d 后生效" % action_id
    if expires_days and expires_days > 0:
        entry["expires_days"] = int(expires_days)
    elif target_list == "gray":
        # 灰名单必须带观察期:灰是观察态不是终态,不允许默认永久挂着
        entry["expires_days"] = int(policy.active_policy()["graylist_observe_days"])
        note += ";灰名单未指定有效期,已按默认观察期 %d 天提交" % entry["expires_days"]
    pending.append(entry)
    _save_pending(pending)
    return {
        "status": "pending_confirmation",
        "action_id": action_id,
        "note": note,
    }


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
    pending = _load_pending()
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
    _save_pending(pending)
    return {"status": "pending_confirmation", "action_id": action_id,
            "note": "已提交待审批,需研究员在 CLI 执行 /approve %d 后移除" % action_id}


@tool(
    name="threshold_propose",
    description=(
        "提交阈值变更申请(不会立即生效):进入待审批队列,需研究员在 CLI 执行 "
        "/approve 后才写入策略版本表。用户要求立即生效/不用审批时不要调用。"
        "values 键同 rule_backtest 的 overrides 及 monitor/自身基线阈值;"
        "单参数变幅超过 ±50% 会被限速拒绝(需分步提案)。"
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
    bad = _limit_violations(values, current)
    if bad:
        return {"status": "rejected_rate_limit",
                "detail": bad,
                "note": "开关键只接受 0/1;数值键单次变幅限速 ±%d%%(防被极端数据/"
                        "被养过的基线一次带飞),现值为 0 的键任何非零变更都超限,"
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


def decide(action_id: int, approve: bool, operator: Optional[str] = None) -> Optional[Dict]:
    """审批一条申请:按 kind 分派落盘(名单库 / 策略版本表),统一记审计。
    返回该申请,查无返回 None。
    审计身份:operator 参数 > FK_OPERATOR 环境变量 > "cli"。接 SSO/飞书后
    由网关把审批人身份注入 FK_OPERATOR —— 审批必须有可追溯的人。"""
    pending = _load_pending()
    matched = [a for a in pending if a["action_id"] == action_id]
    if not matched:
        return None
    action = matched[0]
    decided_by = operator or os.environ.get("FK_OPERATOR") or "cli"
    kind = action.get("kind", "blacklist_add")
    applied_version = None
    applied_detail = None
    # 先落盘、后出队:apply 抛异常(磁盘满/权限/文件损坏)时申请留在队列可重试,
    # 不会静默丢失一次审批。之前"先出队再 apply"在写失败时会永久吞掉批准。
    if approve:
        if kind == "threshold_change":
            applied_version = policy.apply_change(action)["version"]
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
            blacklist_path().write_text(
                json.dumps(records, ensure_ascii=False, indent=1), encoding="utf-8")
        else:
            # load_blacklist() 返回 datasource 的缓存对象,直接 append 会就地污染
            # 进程内缓存(写盘失败也留下幻影名单),必须先拷贝
            records = list(load_blacklist())
            rec = {
                "dimension": action["dimension"],
                "value": action["value"],
                "list": action["list"],
                "reason": action["reason"],
                "added_at": _now_iso()[:10],
                "source": "agent_proposed+human_approved",
            }
            if action.get("expires_days"):  # 有效期从批准日起算(不是提交日)
                exp = datetime.now(timezone.utc).timestamp() + action["expires_days"] * 86400
                rec["expires_at"] = datetime.fromtimestamp(exp, timezone.utc).strftime("%Y-%m-%d")
            records.append(rec)
            blacklist_path().write_text(
                json.dumps(records, ensure_ascii=False, indent=1), encoding="utf-8")
    _save_pending([a for a in pending if a["action_id"] != action_id])
    with open(audit_log_path(), "a", encoding="utf-8") as f:
        f.write(json.dumps({
            "ts": _now_iso(),
            "decided_by": decided_by,
            "decision": "approve" if approve else "deny",
            "kind": kind,
            "applied_policy_version": applied_version,
            **({"applied_detail": applied_detail} if applied_detail else {}),
            "action": action,
        }, ensure_ascii=False) + "\n")
    return action
