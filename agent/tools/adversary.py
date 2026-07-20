# -*- coding: utf-8 -*-
"""对抗面巡检工具:阈值试探(near-miss)+ 团伙演化增速。

漂移监控(drift.py)看的是"分布变没变";本工具看的是对抗特有的两个信号,
它们在整体分布上可能毫无动静:
- 阈值试探:对手摸到阈值后会贴边飞行 —— R002 阈值 30 秒,一批账号的间隔
  集中出现在 31~45 秒;R003 大额线 1000,订单批量出现在 900~999。监控
  "刚好没命中"的账号密度,涨起来就是对手在适应,这时候整体 PSI 往往还稳。
- 团伙演化:图谱(graph_relations)是静态快照,团伙是活的 —— 一台设备上的
  账号数一周从 3 涨到 15,增速本身就是最强信号,不用等任何规则命中。

近阈带按规则方向取且带宽不对称(NEAR_BAND_ABOVE/BELOW,取值依据见常量
注释)。报警沿用 drift 的双条件纪律(翻倍且绝对变幅超 5pp,小样本桶不
报警)—— 贴边密度天然波动,单条件必然误报。
"""
from collections import defaultdict
from typing import Dict, List, Optional

from . import tool
from .drift import (MIN_PSI_SAMPLES, _bucket_account_features, _bucket_events,
                    _head_partial, _hit_rate_alarm, _tail_partial, drift_alert_text)
from .policy import active_policy

# 近阈带宽按方向分开:above(下触发规则的规避者,如把间隔拉到 30s 线上方)
# 行为上有安全余量诉求,带取 1~1.5 倍;below(上触发规则的规避者,如大额线
# 下压单)会贴得很紧 —— 998 元的单不会退到 700,带太宽会把大量合法大额单
# 算进"贴边密度",信号被稀释。below 带取 0.9 倍:[0.9*thr, thr)。
NEAR_BAND_ABOVE = 1.5
NEAR_BAND_BELOW = 0.9
GANG_NEW_MIN = 3    # 单资源在最近一桶新增账号数达到此值即报增速告警


def _near_watches(p: Dict) -> List[Dict]:
    """从当前策略推导要盯的 (特征, 阈值, 方向)。方向 = 对手会藏在哪一侧:
    below_triggers(值 <= 阈值触发)的规避者贴在阈值上方,反之贴下方。"""
    return [
        {"feature": "min_gap_seconds", "rule": "R002",
         "threshold": p["r002_max_gap_seconds"], "evade_side": "above"},
        {"feature": "coupon_claims", "rule": "R002",
         "threshold": p["r002_min_events"], "evade_side": "below"},
        {"feature": "order_amount_max", "rule": "R003",
         "threshold": p["r003_high_amount"], "evade_side": "below"},
    ]


def _in_band(v: float, thr: float, side: str) -> bool:
    if side == "above":
        return thr < v <= thr * NEAR_BAND_ABOVE
    return thr * NEAR_BAND_BELOW <= v < thr


@tool(
    name="adversary_watch",
    description=(
        "对抗面巡检:①阈值试探 —— 逐桶监控'贴着阈值刚好不命中'的账号密度"
        "(间隔贴 R002 线上方/金额贴 R003 线下方),翻倍且超 5pp 报警,是对手"
        "适应阈值的信号(此时整体 PSI 往往还稳);②团伙演化 —— 设备/IP 账号数"
        "逐桶增速,最近一桶新增 ≥3 告警。答'对手在不在适应''团伙在不在扩张'。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "time_grain": {"type": "string", "enum": ["day", "hour"],
                           "description": "分桶粒度,默认 day"},
            "benchmark_buckets": {"type": "integer",
                                  "description": "作为基准的最早桶数,默认 1"},
        },
    },
)
def adversary_watch(time_grain: str = "day", benchmark_buckets: int = 1):
    if time_grain not in ("day", "hour"):
        return {"error": "time_grain 只支持 day / hour"}
    p = active_policy()
    buckets = _bucket_events(time_grain)
    labels = sorted(buckets)
    if len(labels) < 2:
        return {"found": False, "time_grain": time_grain, "bucket_count": len(labels),
                "note": "分桶后不足 2 个桶,无从比较;换更细的 time_grain 试试"}
    benchmark_buckets = max(1, min(benchmark_buckets, len(labels) - 1))
    bench_labels = labels[:benchmark_buckets]
    rows_by_label = {lb: _bucket_account_features(buckets[lb]) for lb in labels}
    alarms: List[str] = []

    # ① 阈值试探:逐桶近阈账号占比(分母 = 该特征非缺失的账号)
    watches = []
    for w in _near_watches(p):
        feat, thr, side = w["feature"], w["threshold"], w["evade_side"]

        def _rate(lbs: List[str]):
            vals = [r[feat] for lb in lbs for r in rows_by_label[lb]
                    if r.get(feat) is not None]
            hits = sum(1 for v in vals if _in_band(v, thr, side))
            return (round(hits / len(vals), 4), hits, len(vals)) if vals else (None, 0, 0)

        bench_rate, _, bench_n = _rate(bench_labels)
        trend, alarmed = [], []
        for lb in labels:
            if lb in bench_labels:
                continue
            rate, hits, n = _rate([lb])
            entry = {"bucket": lb, "rate": rate}
            if (rate is not None and bench_rate is not None
                    and min(n, bench_n) >= MIN_PSI_SAMPLES
                    and rate > bench_rate and _hit_rate_alarm(bench_rate, rate)):
                entry["alarm"] = True
                alarmed.append((rate, lb))
            trend.append(entry)
        if alarmed:  # 同一监控项聚合成一条告警,逐桶明细在 trend 里
            worst_rate, worst_lb = max(alarmed)
            alarms.append("%s 近阈带(%s %s)密度走高:基准 %.1f%%,最高 %.1f%%(%s),"
                          "共 %d 桶超线,疑似阈值试探" % (
                              w["rule"], feat, side, 100 * bench_rate,
                              100 * worst_rate, worst_lb, len(alarmed)))
        watches.append({**w,
                        "band": ("(%g, %g]" % (thr, thr * NEAR_BAND_ABOVE)
                                 if side == "above" else
                                 "[%g, %g)" % (thr * NEAR_BAND_BELOW, thr)),
                        "benchmark_rate": bench_rate, "trend": trend})

    # ② 团伙演化:共享资源(设备/IP)上账号的逐桶累计数,盯增速不盯存量
    first_seen: Dict[tuple, Dict[str, str]] = defaultdict(dict)  # (dim,val) -> uid -> 首见桶
    for lb in labels:
        for e in buckets[lb]:
            for dim in ("device_id", "ip"):
                fs = first_seen[(dim, e[dim])]
                if e["uid"] not in fs:
                    fs[e["uid"]] = lb
    growing = []
    for (dim, val), fs in first_seen.items():
        if len(fs) < 2:
            continue
        new_last = sum(1 for b in fs.values() if b == labels[-1])
        # counts 与 buckets 顺序对齐的累计账号数(瘦身:不重复桶名)
        entry = {"dimension": dim, "value": val, "accounts_total": len(fs),
                 "new_in_last_bucket": new_last,
                 "counts": [sum(1 for b in fs.values() if b <= lb) for lb in labels]}
        if new_last >= GANG_NEW_MIN:
            entry["alarm"] = True
            alarms.append("%s=%s 最近一桶新增 %d 个账号(累计 %d),团伙疑似扩张" % (
                dim, val, new_last, len(fs)))
        growing.append(entry)
    growing.sort(key=lambda g: (-g["new_in_last_bucket"], -g["accounts_total"]))

    tail_partial = _tail_partial(buckets, labels)
    head_partial = _head_partial(buckets, labels)
    out = {
        "found": True,
        "time_grain": time_grain,
        "bucket_count": len(labels),
        "benchmark_buckets": bench_labels,
        "tail_bucket_partial": tail_partial,
        **({"benchmark_note": "基准桶 %s 事件量不足后续中位桶一半,可能采集不完整,"
                              "PSI/密度基准参考价值低,建议 benchmark_buckets>=2"
                              % labels[0]}
           if benchmark_buckets == 1 and head_partial else {}),
        "policy_version": p["_version"],
        "near_miss": watches,
        "gang_growth": growing[:8],
        "gang_growth_note": "按最近一桶新增账号数降序,只列前 8;counts 为逐桶累计,与 bucket 顺序对齐",
        "alarm": bool(alarms),
        "alarms": alarms,
        "note": "近阈密度告警是调阈值的强信号(对手已适应当前线),但改线仍走"
                "shadow_backtest → threshold_propose 全流程",
    }
    out["alert_text"] = drift_alert_text(out)
    return out
