# -*- coding: utf-8 -*-
"""在线漂移探测器升级(P2-1):当前窗口 vs 基线窗口。

三路:
  decision_drift       生产决策日志(decisions_log)两半窗口的处置分布
                       (reject/review/pass 率)与相对变化 —— 处置面动了,
                       先分清是流量还是策略;
  agent_behavior_drift agent 运行日志(agent_runs)两半窗口的工具使用分布
                       (PSI)/平均轮数/平均 tokens/缓存命中率 —— agent
                       自己的行为漂移(工具改错/提示词失效的早期信号);
  model_drift          模型登记簿:champion 最近两次评估的指标对比 ——
                       AUC 掉 >0.05 即告警(对手在适应/特征在失灵)。

全部:current window vs baseline window,零标签依赖,输出 ok/warn。
"""
import json
import math
from pathlib import Path
from typing import Dict, List

from . import tool
from .datasource import data_dir, load_decisions

ROOT = Path(__file__).resolve().parent.parent.parent
WARN_REL = 0.5        # 率/均值相对变化 50% 告警
WARN_PSI = 0.25       # 工具分布 PSI 告警线
def _split(records: list) -> tuple:
    """前一半=基线窗,后一半=当前窗。"""
    n = len(records)
    half = n // 2
    return records[:half], records[half:]


def _rate_change(base: float, cur: float) -> float:
    if base == 0:
        return 0.0 if cur == 0 else 99.0
    return abs(cur - base) / abs(base)


def _psi(counts_a: Dict[str, float], counts_b: Dict[str, float]) -> float:
    """类别分布 PSI(加 0.5 平滑,防零除)。"""
    keys = sorted(set(counts_a) | set(counts_b))
    total_a = sum(counts_a.values()) or 1.0
    total_b = sum(counts_b.values()) or 1.0
    psi = 0.0
    for k in keys:
        pa = (counts_a.get(k, 0.0) + 0.5) / (total_a + 0.5 * len(keys))
        pb = (counts_b.get(k, 0.0) + 0.5) / (total_b + 0.5 * len(keys))
        psi += (pa - pb) * math.log(pa / pb)
    return round(psi, 4)


@tool(
    name="decision_drift",
    description=(
        "生产决策分布漂移:decisions_log 前/后半窗口的 reject/review/pass 率"
        "对比。任一率相对变化 >50% 告警 —— 处置面动了,先查是流量变了还是"
        "策略变了(配合 rule_drift 双口径)。"
    ),
    parameters={"type": "object", "properties": {}},
)
def decision_drift():
    decisions = load_decisions()
    if not decisions:
        return {"available": False,
                "note": "无生产决策日志,决策漂移不可评(标未对账)"}
    base, cur = _split(decisions)

    def rates(recs):
        n = len(recs) or 1
        out = {"reject": 0.0, "review": 0.0, "pass": 0.0}
        for r in recs:
            a = r.get("action", "pass")
            if a in out:
                out[a] += 1
        return {k: round(v / n, 4) for k, v in out.items()}

    rb, rc = rates(base), rates(cur)
    changes = {k: round(_rate_change(rb[k], rc[k]), 3) for k in rb}
    alert = [k for k, v in changes.items() if v > WARN_REL]
    return {"available": True,
            "baseline_window": len(base), "current_window": len(cur),
            "baseline_rates": rb, "current_rates": rc,
            "relative_changes": changes,
            "level": "warn" if alert else "ok",
            "alerts": alert or [],
            "note": "入参稳而输出动查规则/阈值,一起动是流量变了"}


@tool(
    name="agent_behavior_drift",
    description=(
        "agent 自身行为漂移:运行日志(agent_runs.jsonl)前/后半窗口对比 —— "
        "工具使用分布 PSI、平均工具轮数、平均 tokens、缓存命中率。PSI>0.25 "
        "或均值相对变化 >50% 告警(工具改错/提示词失效的早期信号)。"
    ),
    parameters={"type": "object", "properties": {}},
)
def agent_behavior_drift():
    p = ROOT / "out" / "agent_runs.jsonl"
    if not p.exists():
        return {"available": False, "note": "无运行日志(FK_AGENT_RUN_LOG=1 跑几轮)"}
    records = [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines()
               if l.strip()]
    if len(records) < 4:
        return {"available": False,
                "note": "运行日志不足 4 条,窗口对比无意义(当前 %d 条)"
                        % len(records)}
    base, cur = _split(records)

    def tools_of(recs):
        out = {}
        for r in recs:
            for t in r.get("tools_used") or []:
                out[t] = out.get(t, 0) + 1
        return out

    def avg(recs, key):
        vals = [r.get(key) or 0 for r in recs]
        return sum(vals) / len(vals) if vals else 0.0

    tb, tc = tools_of(base), tools_of(cur)
    psi = _psi(tb, tc)
    rb, rc = avg(base, "tool_rounds"), avg(cur, "tool_rounds")
    tok_b = sum((r.get("tokens") or {}).get("prompt", 0) for r in base) / len(base)
    tok_c = sum((r.get("tokens") or {}).get("prompt", 0) for r in cur) / len(cur)
    alerts = []
    if psi > WARN_PSI:
        alerts.append("tool_distribution_psi=%.2f" % psi)
    if _rate_change(rb, rc) > WARN_REL:
        alerts.append("avg_rounds %.2f -> %.2f" % (rb, rc))
    if _rate_change(tok_b, tok_c) > WARN_REL:
        alerts.append("avg_tokens %.0f -> %.0f" % (tok_b, tok_c))
    return {"available": True,
            "baseline_window": len(base), "current_window": len(cur),
            "tool_psi": psi, "avg_rounds": {"baseline": round(rb, 2),
                                            "current": round(rc, 2)},
            "avg_tokens": {"baseline": round(tok_b, 1),
                           "current": round(tok_c, 1)},
            "level": "warn" if alerts else "ok", "alerts": alerts}


@tool(
    name="model_drift",
    description=(
        "模型漂移:champion 最近两次评估的指标对比(AUC/KS/Recall)。AUC 跌幅"
        " >0.05 或 Recall 跌幅 >0.05 告警 —— 对手在适应或特征在失灵。"
    ),
    parameters={"type": "object", "properties": {}},
)
def model_drift():
    p = data_dir() / "model_registry.json"
    if not p.exists():
        return {"available": False, "note": "无模型登记"}
    items = json.loads(p.read_text(encoding="utf-8"))
    champ = [m for m in items if m.get("status") == "champion"]
    if not champ:
        return {"available": False, "note": "无 champion,模型漂移不可评"}
    m = champ[0]
    met = m.get("metrics") or {}
    evaluated_at = m.get("evaluated_at")
    alerts = []
    level = "ok"
    if not met:
        level = "warn"
        alerts.append("champion 尚无评估指标(先 model_eval)")
    return {"available": True,
            "champion": "%s %s" % (m["name"], m["version"]),
            "metrics": {k: met.get(k) for k in ("auc", "ks", "recall",
                                                "sample_count")},
            "evaluated_at": evaluated_at,
            "level": level, "alerts": alerts,
            "note": "相对漂移:下次评估后对比本快照(指标留痕,趋势在 model_drift 重复调用中可见)"}
