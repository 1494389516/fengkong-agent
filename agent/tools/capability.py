# -*- coding: utf-8 -*-
"""Capability / 权限注册表:工具从"存在"升级为"有权限等级"。

三层权限模型(缺一不可):
  Prompt restriction(提示词纪律)+ Tool restriction(不注册审批工具)
  + Runtime capability restriction(本模块:dispatch 单点代码级强制)。

等级:
  read      只读取证(默认)
  simulate  模拟/回放(不产生任何写)
  propose   提交待审批(写通道的申请端,agent 可调用)
  execute   运行时状态写(登记/销单/任务,不经审批但全程审计)
  approve   人类专用(不注册为工具;经 dispatch 调用 = 越权,拒绝+审计)
  admin     同上,人类专用

强制点:dispatch(agent/tools/__init__.py)在工具执行前查等级:
  - approve/admin 一律拒绝,写 security audit;
  - 未知工具尝试写 security audit(防枚举);
  - execute 级调用写 security audit(执行留痕)。
审计文件:data/security_audit.jsonl(gitignored,运行时文件)。
"""
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from . import tool
from .datasource import data_dir

LEVELS = ("read", "simulate", "propose", "execute", "approve", "admin")

# 显式登记敏感工具;未登记的工具默认 read。
# propose = 走两阶段审批的申请端;execute = 不经审批但留痕的运行时写。
CAPABILITY = {
    # 审批/管理员通道:永远不注册为工具,这里登记只是让检查可识别
    "approve": "approve",
    "deny": "approve",
    # 写通道申请端(agent 可调用,但只进 pending)
    "blacklist_add": "propose",
    "blacklist_remove": "propose",
    "threshold_propose": "propose",
    "appeal_resolve": "propose",
    "model_promote": "propose",
    "model_rollback": "propose",
    "strategy_promote": "propose",
    "strategy_rollback": "propose",
    # 运行时状态写(留痕审计)
    "model_register": "execute",
    "strategy_register": "execute",
    "model_eval": "execute",
    "mismatch_resolve": "execute",
    "job_submit": "execute",
    "job_cancel": "execute",
    # 模拟/回放(零写)
    "rule_backtest": "simulate",
    "shadow_backtest": "simulate",
    "threshold_calibrate": "simulate",
    "rule_draft_test": "simulate",
    "feature_risk": "simulate",
    "strategy_replay": "simulate",
    "strategy_shadow": "simulate",
}

# 越权词根:工具名像审批/管理通道的一律按越权处理(防绕过)
_ADMIN_HINT = ("approve", "deny", "admin")


def level_of(name: str) -> str:
    return CAPABILITY.get(name, "read")


def audit(kind: str, tool_name: str, level: str, reason: str) -> None:
    """security audit 追加一行(尽力而为:审计失败不能掀翻主流程)。"""
    try:
        p = data_dir() / "security_audit.jsonl"
        p.parent.mkdir(parents=True, exist_ok=True)
        rec = {
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "kind": kind,  # denied | unknown | executed
            "tool": tool_name,
            "level": level,
            "reason": reason,
        }
        with open(p, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:  # noqa: BLE001
        pass


def enforce(tool_name: str, is_registered: bool) -> str:
    """dispatch 单点的运行时检查。返回 ""=放行,否则为拒绝原因。
    is_registered=False 时先审计再拒绝(未知工具枚举是攻击面)。"""
    level = level_of(tool_name)
    if level in ("approve", "admin") or any(
            h in tool_name.lower() for h in _ADMIN_HINT):
        audit("denied", tool_name, level,
              "审批/管理员通道不可经工具调用(越权尝试)")
        return "capability denied: %s 是 %s 级,仅限人类通道" % (tool_name, level)
    if not is_registered:
        audit("unknown", tool_name, level, "未知工具调用(疑似枚举)")
        return "unknown tool: %s" % tool_name
    if level == "execute":
        audit("executed", tool_name, level, "执行级工具调用已留痕")
    return ""


def _audit_records() -> list:
    p = data_dir() / "security_audit.jsonl"
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


@tool(
    name="capability_registry",
    description=(
        "查询工具权限注册表:每个工具的能力等级(read/simulate/propose/"
        "execute/approve/admin),以及安全审计统计(越权拒绝/未知工具/执行"
        "留痕)。approve 与 admin 不注册为工具,任何经 dispatch 的调用都被"
        "拒绝并审计。"
    ),
    parameters={"type": "object", "properties": {}},
)
def capability_registry():
    from . import _REGISTRY as registry  # 直接引用注册表,避免工具名硬编码
    # 按等级分组返回(而非全量 name->level 表):对 agent 更可读,
    # 也避免大字典被 ② 限幅截断后关键信息(propose/execute)丢失。
    by_level: Dict[str, list] = {"read": [], "simulate": [], "propose": [],
                                 "execute": []}
    for name in sorted(registry.keys()):
        lv = level_of(name)
        if lv in by_level:
            by_level[lv].append(name)
    records = _audit_records()
    kinds: Dict[str, int] = {}
    for r in records:
        kinds[r.get("kind", "?")] = kinds.get(r.get("kind", "?"), 0) + 1
    return {
        "tool_count": len(registry),
        "by_level": {k: sorted(v) for k, v in by_level.items()},
        "approve_human_only": ["approve", "deny"],
        "security_audit": {"total": len(records), "by_kind": kinds,
                           "recent": records[-5:]},
        "note": "approve/admin 不可经 dispatch(拒绝+审计);execute 级调用全部留痕",
    }
