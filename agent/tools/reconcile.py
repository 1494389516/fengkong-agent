# -*- coding: utf-8 -*-
"""模拟一致性对账:agent 本地规则模拟 vs 生产决策日志。

架构军规:风控系统是唯一事实源,agent 的规则/阈值只是镜像 —— 镜像必须
对账。本地 rule_eval 与生产引擎必然存在实现差异(窗口边界/口径/阈值同步
时序),对不上时诚实的行为是把模拟类结论降级,而不是继续输出。

decisions_log.json 设定由生产引擎写入(骨架里手工模拟,并故意埋了三条
不一致,演练"生产侧改了策略没同步"的场景)。不一致率超过
max_sim_mismatch_rate(policy)时:
- consistency_check 给出失信判定与警告;
- rule_backtest / shadow_backtest / threshold_calibrate 的返回自动附
  sim_consistency 失信标记 —— 模拟器失准时,用它算出的指标不可作为
  变更依据。这是机器强制,不只是提示词约束。
无日志的数据集(如生成集)优雅降级:对账不可用,工具不附标记,
但模拟结论应标注"未对账"。
"""
from typing import Dict, Optional

from . import tool
from .datasource import data_dir, load_decisions, load_events
from .policy import active_policy
from .rules import rule_eval

_cache: Dict = {}

_STATE_FILES = ("events_sample.json", "decisions_log.json", "thresholds.json",
                "blacklist.json", "accounts.json")


def _state_key():
    out = []
    for name in _STATE_FILES:
        p = data_dir() / name
        out.append(p.stat().st_mtime_ns if p.exists() else 0)
    return tuple(out)


def reconcile() -> Optional[Dict]:
    """全量对账。无日志返回 None。结果按数据/策略文件 mtime 缓存;
    覆盖(what-if)生效期间不落缓存,避免污染。"""
    decisions = load_decisions()
    if decisions is None:
        return None
    key = _state_key()
    hit = _cache.get("r")
    if hit and hit[0] == key:
        return hit[1]
    events: Dict = {}
    for e in load_events():
        events.setdefault((e["uid"], e["ts"]), e)
    compared = agree = orphan = 0
    mismatches = []
    for d in decisions:
        ev = events.get((d["uid"], d["ts"]))
        if ev is None:
            orphan += 1  # 日志有、事件表没有:数据面就没对齐
            continue
        local = rule_eval(ev)  # 默认回放口径:当时的特征 + 当时的本地策略版本
        compared += 1
        if local["action"] == d["action"]:
            agree += 1
        else:
            mismatches.append({
                "uid": d["uid"], "ts": d["ts"],
                "local": local["action"], "prod": d["action"],
                "local_rules": [h["rule_id"] for h in local["hits"]],
                "prod_rules": d.get("rules", []),
            })
    rate = round(len(mismatches) / compared, 4) if compared else 0.0
    threshold = active_policy()["max_sim_mismatch_rate"]
    result = {
        "compared": compared,
        "agree": agree,
        "mismatch_rate": rate,
        "max_sim_mismatch_rate": threshold,
        "trusted": rate <= threshold,
        "mismatches": mismatches,
        "orphan_decisions": orphan,
        "uncovered_events": len(events) - compared,
    }
    if not result["trusted"]:
        result["warning"] = (
            "模拟器失信:本地模拟与生产决策不一致率 %.1f%% 超过阈值 %.1f%%,"
            "回测/影子/校准等模拟类结论不可作为变更依据,先排查规则与阈值是否与生产同步"
            % (100 * rate, 100 * threshold))
    if not active_policy()["_overridden"]:
        _cache["r"] = (key, result)
    return result


def sim_trust() -> Optional[Dict]:
    """给模拟类工具附带的紧凑失信标记。无日志返回 None(不附)。"""
    r = reconcile()
    if r is None:
        return None
    out = {"mismatch_rate": r["mismatch_rate"], "trusted": r["trusted"]}
    if not r["trusted"]:
        out["warning"] = r["warning"]
    return out


@tool(
    name="consistency_check",
    description=(
        "对账:agent 本地规则模拟 vs 生产决策日志,逐事件比对处置结论。返回"
        "一致率、不一致清单(本地/生产的动作与命中规则)、失信判定与告警。"
        "任何基于模拟的结论(rule_backtest/shadow_backtest/threshold_calibrate)"
        "之前都应确认对账可信;失信时先排查规则与阈值同步,不要继续输出模拟指标。"
    ),
    parameters={"type": "object", "properties": {}},
)
def consistency_check():
    r = reconcile()
    if r is None:
        return {"available": False,
                "note": "当前数据集无生产决策日志,对账不可用;模拟结论请标注'未对账'"}
    return {"available": True, **r}
