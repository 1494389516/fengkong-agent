# -*- coding: utf-8 -*-
"""统一事件回放引擎:event → 特征快照 → 策略版本 → 引擎 → decision,
全程版本记录 —— 反事实分析、策略实验、事故复盘的底座。

纪律:
  - 确定性:相同 event + 相同 policy/strategy/model 版本,本地路径必然
    得到相同结果(输入指纹 + 版本号全部记录,可复现可对质);
  - 无生产副作用:回放绝不写 pending/audit/mismatch/名单/策略;
  - 版本溯源:每条结果带 input_fingerprint / policy_version_used /
    strategy_version / model_version / source / degraded;
  - 回放支持 batch(与引擎批量判定对齐);
  - 回放结果可直接进 eval(本模块被 eval 层 import)。

判定本身仍走 engine 适配器(唯一判定入口):带覆盖(策略版本/策略注册表
版本)时适配器强制本地模拟(假想阈值不发给生产引擎);无覆盖时按 as-of
或当前口径走引擎。
"""
import hashlib
import json
from typing import Any, Dict, List, Optional


def _canon_event(obj: Any) -> Any:
    """指纹口径:整数值的 int/float 视为同一事件(JSON 里 1 与 1.0 字面量不同)。
    bool 是 int 子类,必须先排除,否则 True 会变成 1。"""
    if isinstance(obj, dict):
        return {k: _canon_event(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_canon_event(v) for v in obj]
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, float) and obj.is_integer() and abs(obj) < 2 ** 53:
        return int(obj)
    return obj


def event_fingerprint(event: Dict[str, Any]) -> str:
    """事件规范化指纹:同一事件的语义等价序列化 -> 同一指纹。"""
    blob = json.dumps(_canon_event(event), ensure_ascii=False,
                      sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def replay_event(event: Dict[str, Any], policy_version: Optional[int] = None,
                 model_version: str = "", strategy_version: str = "",
                 use_current_policy: bool = False) -> Dict[str, Any]:
    """回放单个事件。policy_version=策略版本表的版本号(按该版本阈值);
    strategy_version="name:version"(策略注册表阈值覆盖);model_version 仅
    血缘记录。三者叠加时阈值覆盖合并(策略注册表优先于版本表?不 ——
    显式报错拒绝歧义:同时给两个阈值源是口径事故)。"""
    from .tools import policy as P

    override: Dict[str, float] = {}
    src = []
    if policy_version is not None and strategy_version:
        raise ValueError("policy_version 与 strategy_version 同时给定:"
                         "两个阈值源是口径事故,请二选一")
    if strategy_version:
        from .tools.strategy_registry import _find as _sfind
        from .tools.strategy_registry import _load as _sload
        name, ver = strategy_version.split(":", 1)
        entry = _sfind(_sload(), name, ver)
        if entry is None:
            raise ValueError("策略未登记: %s" % strategy_version)
        override.update(entry["thresholds"])
        src.append("strategy:%s" % strategy_version)
    if policy_version is not None:
        override.update(P.snapshot_at_version(policy_version))
        src.append("policy:v%d" % policy_version)
    if model_version:
        from .tools.model_registry import _find as _mfind
        from .tools.model_registry import _load as _mload
        name, ver = model_version.split(":", 1)
        if _mfind(_mload(), name, ver) is None:
            raise ValueError("模型未登记: %s" % model_version)
    from .engine import evaluate_event
    prev = P.set_overrides(override)
    try:
        r = evaluate_event(event, use_current_policy=use_current_policy)
    finally:
        P.restore_overrides(prev)
    r["replay"] = True
    r["input_fingerprint"] = event_fingerprint(event)
    r["policy_version_used"] = (policy_version if policy_version is not None
                                else r.get("policy_version"))
    r["strategy_version"] = strategy_version or None
    r["model_version"] = model_version or None
    r["threshold_sources"] = src
    return r


def replay_batch(events: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
    """批量回放:与输入顺序对齐,逐条含指纹与版本记录。"""
    return [replay_event(e, **kwargs) for e in events]
