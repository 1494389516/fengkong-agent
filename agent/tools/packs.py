# -*- coding: utf-8 -*-
"""按任务裁剪工具集:会话只把当前任务需要的 schema 发给模型。

82 个工具的 schema 每请求随行 ~36k chars。研究员一次只做一类事
(查账号 / 值班日报 / 查团伙 / 调策略),全量暴露会同时抬 cache miss
底价和选错工具的概率。包是发送面过滤,不是注销 —— 注册表仍完整,
eval 结构性预算继续按全量计;dispatch 在包激活时拒绝包外调用
(代码层,不只靠模型不看见)。

包:
  investigate  账号调查
  duty         值班日报
  graph        团伙排查
  strategy     回测/调参/试衣间
  analyst      上四者并集(日常 Copilot 默认,覆盖 24 个黄金案例工具面)
  full         全量(治理/模型/Job/实验,评估与平台操作)

切换:环境变量 FK_TOOL_PACK,或 CLI `/pack <name>`(会 reset 上下文,
因为 schema 前缀变了,缓存必 miss)。
"""
import os
from typing import Dict, FrozenSet, Optional, Set

PACK_ENV = "FK_TOOL_PACK"
DEFAULT_PACK = "analyst"
PACK_NAMES = ("investigate", "duty", "graph", "strategy", "analyst", "full")

# 每个非 full 包都带:判定通道、权限查询、数据体检(换数据后的第一件事)
_ALWAYS = frozenset({
    "engine_status", "capability_registry", "data_health_check",
})

_INVESTIGATE = frozenset({
    "account_profile", "account_monitor", "feature_stats", "rule_eval",
    "blacklist_query", "blacklist_add", "blacklist_remove",
    "device_intel", "ip_intel", "report_query",
    "appeal_review", "appeal_resolve",
    "chart_account_timeline", "decision_explain", "decision_trace",
    "audit_query", "policy_history", "graylist_review",
})

_DUTY = frozenset({
    "daily_brief", "duty_ops", "scan_all",
    "feature_drift", "rule_drift", "adversary_watch", "chart_drift_dashboard",
    "graylist_review", "appeal_review",
    "mismatch_queue", "incident_list", "incident_open", "incident_update",
    "feedback_pipeline", "decision_drift", "agent_behavior_drift",
    "feature_health_check", "production_readiness_check",
})

_GRAPH = frozenset({
    "graph_relations", "account_profile", "device_intel", "ip_intel",
    "blacklist_query", "blacklist_add", "chart_cohort_features", "scan_all",
})

_STRATEGY = frozenset({
    "rule_backtest", "shadow_backtest", "threshold_calibrate",
    "threshold_propose", "chart_threshold_sweep", "chart_cohort_features",
    "feature_risk", "rule_draft_test", "feature_catalog",
    "policy_history", "feature_drift", "rule_drift",
    "feature_validate", "feature_health_check", "consistency_check",
    "build_dataset", "model_list", "model_status", "model_compare",
    "strategy_list", "strategy_diff", "strategy_replay", "strategy_shadow",
})

PACKS: Dict[str, Optional[FrozenSet[str]]] = {
    "investigate": _ALWAYS | _INVESTIGATE,
    "duty": _ALWAYS | _DUTY,
    "graph": _ALWAYS | _GRAPH,
    "strategy": _ALWAYS | _STRATEGY,
    "analyst": _ALWAYS | _INVESTIGATE | _DUTY | _GRAPH | _STRATEGY,
    "full": None,
}

# 进程内当前包。None 未设置时 schemas/dispatch 视为 full(eval 默认)。
# Agent / CLI 会显式 set_active_pack。
_active_pack = "full"


def normalize(pack: Optional[str]) -> str:
    name = (pack or "full").strip().lower()
    if name not in PACKS:
        raise ValueError("未知工具包 %r,可选: %s" % (pack, "/".join(PACK_NAMES)))
    return name


def current() -> str:
    return _active_pack


def set_active_pack(pack: str) -> Dict:
    """切换进程内发送面。返回包名与工具数,供 CLI 展示。"""
    global _active_pack
    _active_pack = normalize(pack)
    names = tool_names(_active_pack)
    return {"pack": _active_pack, "tool_count": len(names)}


def tool_names(pack: Optional[str] = None) -> Set[str]:
    """该包实际会发给模型的工具名。full / None = 注册表全集。
    包里写了但未注册的名字会被丢掉(防拼写把包撑破,eval 会抓缺失)。"""
    from . import _REGISTRY
    key = normalize(pack if pack is not None else _active_pack)
    spec = PACKS[key]
    registered = set(_REGISTRY)
    if spec is None:
        return registered
    return set(spec) & registered


def allows(name: str, pack: Optional[str] = None) -> bool:
    key = normalize(pack if pack is not None else _active_pack)
    if PACKS[key] is None:
        return True
    return name in tool_names(key)


def env_default() -> str:
    """CLI/Agent 启动时的包:FK_TOOL_PACK 优先,否则 analyst。"""
    raw = os.environ.get(PACK_ENV)
    if raw:
        return normalize(raw)
    return DEFAULT_PACK
