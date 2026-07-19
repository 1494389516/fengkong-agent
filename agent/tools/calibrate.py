# -*- coding: utf-8 -*-
"""阈值校准工具:人群基线 + 误伤预算(FPR)→ 建议阈值,含漂移告警与影子对比。

方法论:"阈值设多少"是伪问题,真问题是"愿意误伤多少" —— 人拍的是 FPR 预算,
阈值从基线分位数机械推导(如 gap 阈值 = 只有 FPR 比例账号的最短间隔低于它)。

两条安全红线:
- 校准永不直接生效:输出建议,提交走 threshold_propose(限速 ±50%),
  生效必须人在 CLI /approve。
- 漂移告警要读反:基线分位数相对上一版快照大幅移动,更可能是有人批量制造
  伪正常流量在"养基线",不是自然变化 —— 告警时先查流量,不要顺手重校准。

可推导集只有分布直接可得的参数(见 _derive);monitor burst 这类需要
全人群窗口分布,暂不推导。样本量太小时建议无意义,看返回值里的 baseline n。
"""
import math
from typing import Dict, List, Optional

from . import tool
from .backtest import backtest, shadow_compare
from .datasource import load_labels
from .drift import PSI_ALARM, psi_against_edges
from .featurelib import feature_values, population_baseline
from .policy import active_policy, latest_baseline_snapshot

DRIFT_ALARM_RATIO = 0.3  # 旧快照(无 deciles)回退口径:P99 变幅超 30% 告警


def _quantile(vals: List[float], q: float) -> Optional[float]:
    """升序列表的 q 分位(下取整索引),空列表返回 None。"""
    if not vals:
        return None
    idx = min(len(vals) - 1, max(0, math.ceil(q * len(vals)) - 1))
    return vals[idx]


def _derive(fpr_budget: float) -> Dict[str, float]:
    """FPR 预算 → 建议阈值。方向要各自想清楚:
    gap 越小越可疑 → 取低分位;count/amount 越大越可疑 → 取高分位。"""
    out = {}
    v = _quantile(feature_values("min_gap_seconds"), fpr_budget)
    if v is not None:
        out["r002_max_gap_seconds"] = int(v)
    v = _quantile(feature_values("event_count"), 1 - fpr_budget)
    if v is not None:
        out["r002_min_events"] = int(v)
    v = _quantile(feature_values("order_amount_max"), 1 - fpr_budget)
    if v is not None:
        out["r003_high_amount"] = float(int(v))
    return out


@tool(
    name="threshold_calibrate",
    description=(
        "按误伤预算(fpr_budget,默认 0.01)从人群基线推导建议阈值,并检查基线"
        "相对上一策略版本快照的漂移(告警时优先怀疑伪正常流量在'养基线',勿直接"
        "采纳)。返回基线分位数、建议值 vs 现值、有标签时 normal 账号上的实测误伤率、"
        "以及建议值的影子回测。建议只是提案素材:提交用 threshold_propose,"
        "生效需研究员 /approve。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "fpr_budget": {"type": "number",
                           "description": "可接受的账号级误伤率(0~1),默认 0.01"},
        },
    },
)
def threshold_calibrate(fpr_budget: float = 0.01):
    pol = active_policy()
    baseline = population_baseline()

    # 漂移检查:快照带 deciles(等频切点)时做分布级 PSI —— P99 单点只看尾部,
    # 中段整体位移(温水式养基线)看不见;旧快照无切点则回退 P99 变幅口径。
    ref_version, ref = latest_baseline_snapshot()
    drift_alarms = []
    drift_psi: Dict[str, float] = {}
    if ref:
        for feat, cur in baseline.items():
            snap = ref.get(feat) or {}
            psi = psi_against_edges(snap.get("deciles") or [], feature_values(feat),
                                    expected_n=snap.get("n"))
            if psi is not None:
                drift_psi[feat] = psi
                if psi > PSI_ALARM:
                    drift_alarms.append("%s 相对快照 PSI=%.3f(>%.2f)" % (feat, psi, PSI_ALARM))
            elif snap.get("p99"):
                ratio = abs(cur["p99"] - snap["p99"]) / abs(snap["p99"])
                if ratio > DRIFT_ALARM_RATIO:
                    drift_alarms.append("%s P99 漂移 %.0f%%(%.4g -> %.4g)" % (
                        feat, 100 * ratio, snap["p99"], cur["p99"]))

    suggestions = _derive(fpr_budget)
    changed = {k: v for k, v in suggestions.items() if v != pol[k]}

    # 有标签时:建议阈值在 normal 账号上的实测账号级误伤率(FPR 一致性检查)
    realized_fpr = None
    if changed and load_labels():
        r = backtest(changed)
        if "error" not in r:
            wide = r["operating_points"]["flag=review+reject"]
            denom = wide["fp"] + wide["tn"]
            realized_fpr = round(wide["fp"] / denom, 4) if denom else None

    from .reconcile import sim_trust
    st = sim_trust()
    return {
        "fpr_budget": fpr_budget,
        "policy_version": pol["_version"],
        **({"sim_consistency": st} if st is not None else {}),
        "baseline": baseline,
        "drift_reference_version": ref_version,
        "drift_alarm": bool(drift_alarms),
        "drift_alarms": drift_alarms,
        "drift_psi": drift_psi,
        "suggestions": suggestions,
        "changed_vs_active": changed,
        "realized_fpr_normal_wide": realized_fpr,
        "shadow": shadow_compare(changed) if changed else None,
        "note": "建议仅供提案:threshold_propose 提交(限速 ±50%),CLI /approve 生效",
    }
