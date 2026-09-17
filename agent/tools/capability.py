# -*- coding: utf-8 -*-
"""Capability / 权限注册表:工具从"存在"升级为"有权限等级"。

三层权限模型(缺一不可):
  Prompt restriction(提示词纪律)+ Tool restriction(不注册审批工具)
  + Runtime capability restriction(本模块:dispatch 单点代码级强制)。

等级:
  read      只读取证(必须显式登记,无默认权限)
  simulate  模拟/回放(不修改生产状态;可写可复现实验产物)
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
from contextvars import ContextVar
from contextlib import contextmanager
from dataclasses import dataclass, asdict
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from . import tool
from .datasource import data_dir

# Agent.ask 写入当前用户原话；空上下文不得授予写权限。
# 调查题主动 blacklist_add 曾把待审批队列按团伙数灌满,审批只挡生效不挡提案。
_current_user_text: ContextVar[str] = ContextVar("fk_user_text", default="")

@dataclass(frozen=True)
class RequestScope:
    """Server-issued authorization, never populated from model tool arguments."""
    principal: str
    tenant: str
    dataset: str
    capabilities: tuple
    expires_at: float

    def permits(self, name):
        return (bool(self.principal and self.tenant and self.dataset)
                and self.expires_at > time.time() and name in self.capabilities)

    def snapshot(self):
        return asdict(self)

_current_scope = ContextVar("fk_request_scope", default=None)


def get_scope():
    return _current_scope.get()


@contextmanager
def request_scope(scope, user_text=None):
    token = _current_scope.set(scope)
    text_token = _current_user_text.set(user_text) if user_text is not None else None
    try:
        yield
    finally:
        if text_token is not None:
            _current_user_text.reset(text_token)
        _current_scope.reset(token)


# 点名写入:强动词单独成立;弱动词必须附近有请/帮我/提交,避免"哪些该升黑"误放行。
_WRITE_STRONG = (
    "提交", "拉黑", "加黑", "加白", "加灰", "写入名单",
    "加入黑名单", "加入白名单", "加入灰名单", "加入名单",
    "请改", "帮我改", "改掉", "blacklist_add", "threshold_propose",
    "appeal_resolve",
)
_WRITE_WEAK = ("升黑", "出灰", "晋升", "回滚", "promote", "rollback")
_WRITE_CUE = ("请", "帮我", "给我", "提交")
_WRITE_NEG = ("不", "别", "勿", "禁", "未")
# 越权落地:即使用户点名「提交」,要求当场生效/绕过审批也不放行 propose。
# 陷阱在「立即生效」不在有没有「提交」;「请提交待审批」不含这些词,仍放行。
_IMMEDIATE_LAND = (
    "立即生效", "已生效", "直接生效", "马上生效",
    "不用审批", "不要审批", "不要走审批", "无需审批",
)


def set_user_text(text: str) -> None:
    _current_user_text.set(text or "")


def clear_user_text() -> None:
    _current_user_text.set("")


def get_user_text() -> str:
    return _current_user_text.get() or ""


def user_requests_write(text: str) -> bool:
    """当前用户原话是否点名要求写入。否定窗内的动词不算。"""
    if not text:
        return False
    t = text.lower()
    for kw in _WRITE_STRONG:
        if _positive_hit(t, kw.lower()):
            return True
    for kw in _WRITE_WEAK:
        i = 0
        k = kw.lower()
        while True:
            j = t.find(k, i)
            if j < 0:
                break
            if not _negated_at(t, j) and any(
                    c in t[max(0, j - 8):j + len(k) + 8] for c in _WRITE_CUE):
                return True
            i = j + 1
    return False


def user_requests_immediate_land(text: str) -> bool:
    """用户原话是否要求绕过审批、当场落地。否定窗内不算。"""
    if not text:
        return False
    t = text.lower()
    return any(_positive_hit(t, kw.lower()) for kw in _IMMEDIATE_LAND)


def _negated_at(text: str, idx: int) -> bool:
    return any(n in text[max(0, idx - 4):idx] for n in _WRITE_NEG)


def _positive_hit(text: str, kw: str) -> bool:
    start = 0
    while True:
        i = text.find(kw, start)
        if i < 0:
            return False
        if not _negated_at(text, i):
            return True
        start = i + 1

LEVELS = ("read", "simulate", "propose", "execute", "approve", "admin")

# 所有已注册工具都必须出现在下列清单。新工具漏登记时启动失败,
# 不再 fail-open 成 read。生产状态与敏感导出属 execute;可复现仿真属
# simulate(允许写非生产实验产物);propose 只能写 pending。
READ_TOOLS = frozenset({
    "account_monitor", "account_profile", "adversary_watch",
    "agent_behavior_drift", "appeal_review", "audit_query",
    "blacklist_query", "capability_registry", "consistency_check",
    "daily_brief", "data_health_check", "decision_drift",
    "decision_explain", "decision_trace", "device_intel", "engine_status",
    "experiment_report", "feature_catalog", "feature_diff", "feature_drift",
    "feature_health_check", "feature_parity_check", "feature_stats",
    "feature_validate", "feedback_pipeline", "graph_relations",
    "graylist_metrics", "graylist_review", "incident_list",
    "integration_status", "ip_intel", "job_result", "job_status",
    "label_diff", "mismatch_queue", "model_compare", "model_drift",
    "model_list", "model_status", "policy_history",
    "production_readiness_check", "report_query", "rule_drift", "rule_eval",
    "scan_all", "strategy_diff", "strategy_list", "strategy_validate",
})

CAPABILITY = {
    **{name: "read" for name in READ_TOOLS},
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
    "incident_open": "execute",
    "incident_update": "execute",
    "incident_resolve": "execute",
    "build_dataset": "execute",
    "duty_ops": "execute",
    "experiment_register": "execute",
    "experiment_start": "execute",
    "experiment_stop": "execute",
    "feature_version": "execute",
    "label_version": "execute",
    "label_refresh": "execute",
    "chart_account_timeline": "execute",
    "chart_threshold_sweep": "execute",
    "chart_cohort_features": "execute",
    "chart_drift_dashboard": "execute",
    # 模拟/回放(零写)
    "rule_backtest": "simulate",
    "slice_eval": "simulate",
    "shadow_backtest": "simulate",
    "threshold_calibrate": "simulate",
    "rule_draft_test": "simulate",
    "rule_mining": "simulate",
    "feature_risk": "simulate",
    "strategy_replay": "simulate",
    "strategy_shadow": "simulate",
}

# execute 不等于“模型可自行决定写入”。下面按工具登记用户必须明确表达的
# 动作意图；工具名本身也可作为高级用户的显式指令。
# 用户意图不能替代服务端签发的请求权限。
EXECUTE_INTENT = {
    "model_register": ("登记模型", "注册模型"),
    "strategy_register": ("登记策略", "注册策略"),
    "model_eval": ("评估模型", "模型评估", "跑模型评估"),
    "mismatch_resolve": ("处理对账差异", "解决对账差异", "关闭对账工单"),
    "job_submit": ("提交任务", "启动任务", "创建任务", "跑异步任务"),
    "job_cancel": ("取消任务", "停止任务"),
    "incident_open": ("开事故单", "创建事故", "登记事故"),
    "incident_update": ("更新事故", "追加事故", "记录事故进展"),
    "incident_resolve": ("事故结案", "关闭事故", "解决事故"),
    "duty_ops": ("值班操作", "加入观察", "添加观察", "确认告警", "解除观察"),
    "experiment_register": ("登记实验", "注册实验", "创建实验"),
    "experiment_start": ("启动实验", "开始实验"),
    "experiment_stop": ("停止实验", "结束实验"),
    "feature_version": ("特征快照", "特征版本"),
    "label_version": ("标签快照", "标签版本"),
    "label_refresh": ("刷新标签快照", "刷新标签版本"),
    "chart_account_timeline": ("账号时间线图", "绘制账号时间线", "生成账号时间线"),
    "chart_threshold_sweep": ("阈值扫描图", "绘制阈值扫描", "生成阈值扫描"),
    "chart_cohort_features": ("群体特征图", "绘制群体特征", "生成群体特征"),
    "chart_drift_dashboard": ("漂移看板", "漂移图", "生成漂移看板"),
}

# 越权词根:工具名像审批/管理通道的一律按越权处理(防绕过)
_ADMIN_HINT = ("approve", "deny", "admin")


def level_of(name: str) -> str:
    return CAPABILITY.get(name, "unclassified")


def validate_registry(registry: Dict[str, Any]) -> None:
    """启动门禁:任何注册工具没有显式 capability 都立即失败。"""
    missing = sorted(set(registry) - set(CAPABILITY))
    if missing:
        raise RuntimeError("tool capability 未登记: %s" % ", ".join(missing))
    invalid = sorted(name for name in registry if CAPABILITY[name] not in LEVELS)
    if invalid:
        raise RuntimeError("tool capability 等级无效: %s" % ", ".join(invalid))
    missing_intent = sorted(
        name for name in registry
        if CAPABILITY[name] == "execute"
        and name != "build_dataset"
        and name not in EXECUTE_INTENT)
    if missing_intent:
        raise RuntimeError("execute 工具未登记显式意图: %s"
                           % ", ".join(missing_intent))


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
        from .datasource import append_jsonl
        append_jsonl(p, rec)
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
    if level == "unclassified":
        audit("unclassified", tool_name, level, "工具未显式登记 capability")
        return "capability denied: %s 未登记权限等级" % tool_name
    scope = get_scope()
    if (scope is not None and not scope.permits(tool_name)) or (
            scope is None and level in ("propose", "execute")):
        return "%s blocked: missing, expired or insufficient request scope" % level
    if level == "propose":
        uttered = _current_user_text.get()
        if uttered and user_requests_immediate_land(uttered):
            audit("propose_blocked", tool_name, level,
                  "用户要求立即生效/绕过审批,拒绝 propose")
            return ("propose blocked: 用户要求立即生效或绕过审批,"
                    "只能复核并说明须待审批 /approve,不要调用 %s" % tool_name)
        if not user_requests_write(uttered):
            audit("propose_blocked", tool_name, level,
                  "用户未点名写入,拒绝 propose")
            return ("propose blocked: 用户未明确要求写入,只给文字建议,"
                    "不要调用 %s" % tool_name)
    if level == "execute":
        uttered = _current_user_text.get()
        if (tool_name == "build_dataset"
                and not user_requests_export(uttered)):
            audit("execute_blocked", tool_name, level, "用户未明确要求导出数据集")
            return ("execute blocked: 用户未明确要求导出建模数据集,"
                    "不要调用 build_dataset")
        if (tool_name != "build_dataset"
                and not user_requests_execute(uttered, tool_name)):
            audit("execute_blocked", tool_name, level,
                  "用户未明确要求执行该写操作")
            return ("execute blocked: 用户未明确要求执行 %s,"
                    "只给文字建议或先询问确认" % tool_name)
        audit("executed", tool_name, level, "执行级工具调用已留痕")
    return ""


def user_requests_export(text: str) -> bool:
    if not text:
        return False
    t = text.lower()
    return any(kw in t for kw in (
        "导出数据集", "导出建模样本", "构建数据集", "生成训练集",
        "build_dataset", "export dataset",
    ))


def user_requests_execute(text: str, tool_name: str) -> bool:
    """用户是否明确点名当前 execute 动作；默认拒绝未登记的 execute 工具。"""
    if not text:
        return False
    t = text.lower()
    phrases = (tool_name.lower(),) + tuple(
        kw.lower() for kw in EXECUTE_INTENT.get(tool_name, ()))
    return bool(EXECUTE_INTENT.get(tool_name)) and any(
        _positive_hit(t, phrase) for phrase in phrases)


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
                                 "execute": [], "unclassified": []}
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
        "note": "approve/admin 不可经 dispatch(拒绝+审计);execute 级调用全部留痕;"
                "propose 须点名写入且未要求立即生效,否则硬拒",
    }

# Task constraints are server-issued and inherited by dispatch, never model args.
_investigation = ContextVar('investigation_constraints', default=None)

@contextmanager
def investigation_constraints(snapshot):
    budget = snapshot['budget']
    for key in ('max_tool_calls', 'max_tokens', 'max_graph_nodes'):
        if type(budget.get(key)) is not int or budget[key] <= 0:
            raise ValueError('invalid investigation budget: ' + key)
    state = {'snapshot': snapshot, 'calls': 0, 'tokens': 0}
    token = _investigation.set(state)
    try:
        yield state
    finally:
        _investigation.reset(token)


def investigation_state():
    return _investigation.get()


def constrain_investigation_tool(name, arguments):
    state = _investigation.get()
    if state is None:
        return arguments
    snapshot = state['snapshot']
    state['calls'] += 1
    if state['calls'] > snapshot['budget']['max_tool_calls']:
        raise PermissionError('investigation tool-call budget exhausted')
    arguments = dict(arguments)
    entity = snapshot['entity_ref']
    as_of = snapshot['as_of']
    if name in ('account_profile', 'feature_stats', 'graph_relations'):
        if arguments.get('uid', entity) != entity or arguments.get('device_id'):
            raise PermissionError('entity outside investigation scope')
        arguments['uid'] = entity
        if name in ('feature_stats', 'graph_relations'):
            arguments['as_of_ts'] = as_of
    elif name == 'rule_eval':
        event = dict(snapshot['decision']['event'])
        arguments = {'event': event, 'use_current_policy': False}
    else:
        raise PermissionError('tool outside investigation contract')
    if name == 'graph_relations':
        from .datasource import load_events
        nodes = set()
        for event in load_events(as_of_ts=as_of):
            for field in ('uid', 'device_id', 'ip'):
                if event.get(field):
                    nodes.add((field, str(event[field])))
            if len(nodes) > snapshot['budget']['max_graph_nodes']:
                raise PermissionError('investigation graph-node budget exhausted')
    return arguments
