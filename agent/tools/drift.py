# -*- coding: utf-8 -*-
"""特征漂移画像工具:按时间分桶看特征质量与分布稳定性(PSI)。

口径设计借鉴评分卡工具库 MARS 的数据画像模块,四条约定都是踩过坑的:
- 缺失显式化:业务缺失码(如数仓的 -999)必须显式配置,不自动猜。缺失
  单独算 missing_rate,不混进均值/分位数 —— 否则一个缺失码就把均值拖飞。
- 缺失默认不进 PSI:缺失率要单独观察(它自己就是质量信号),混进 PSI 会
  让"采集故障"和"分布漂移"两种完全不同的问题共享同一个报警。需要复现
  其他口径时显式传 psi_include_missing=true。
- 小箱合并:expected 占比过小的箱并入相邻箱。PSI 对小箱极敏感,几个样本
  的进出就能把 PSI 推过告警线,合并后报警才可信。
- 类别 Top-K + Other:类别特征只保留基准期 Top-K 类,长尾归入 Other ——
  防止新出现的稀有类别(分母为零)让 PSI 发散。

与 calibrate 的漂移告警分工:calibrate 比对"策略版本快照 vs 当前"(审批
时点冻结的基准,防养基线);本工具比对"时间桶 vs 首桶"(探索性,看趋势
在哪一天开始动)。两者都遵守同一纪律:漂移告警先查流量,不要顺手重校准。

纯 stdlib 实现,规则/监控路径保持 pandas-free。
"""
import math
import statistics
import time
from bisect import bisect_left
from collections import Counter, defaultdict
from typing import Dict, List, Optional, Sequence, Tuple

from . import tool
from .datasource import load_events

# PSI 经验阈值(信贷风控通行口径)
PSI_WATCH = 0.1
PSI_ALARM = 0.25
PSI_EPS = 1e-4  # 空箱占比下限:防 log(0),也给"新出现的箱"一个有限惩罚
MIN_PSI_SAMPLES = 30  # 任一侧有效样本低于此不算 PSI:n=6 的样本连 10 个等频箱
#                       都填不满,自比 PSI 都能过告警线 —— 宁可 n/a 不给假信号

DRIFT_FEATURES = ("event_count", "distinct_ip", "distinct_device",
                  "coupon_claims", "min_gap_seconds", "order_amount_max")


# ---------------------------------------------------------------------------
# PSI 核心(纯函数,calibrate 也从这里取,单一实现防口径漂移)
# ---------------------------------------------------------------------------

def _psi(expected_frac: Sequence[float], actual_frac: Sequence[float]) -> float:
    total = 0.0
    for e, a in zip(expected_frac, actual_frac):
        e = max(e, PSI_EPS)
        a = max(a, PSI_EPS)
        total += (a - e) * math.log(a / e)
    return round(total, 4)


def _quantile_edges(vals: Sequence[float], n_bins: int) -> List[float]:
    """基准分布的等频切点(去重)。常数特征返回空 —— 单箱 PSI 恒为 0,
    调用方据此把'没得比'与'比过了没漂移'区分开。"""
    if len(vals) < 2:
        return []
    qs = statistics.quantiles(sorted(vals), n=n_bins, method="inclusive")
    edges = sorted(set(round(q, 6) for q in qs))
    return edges


def _bin_fracs(vals: Sequence[float], edges: List[float]) -> List[float]:
    """按切点分箱后的占比(len(edges)+1 个箱)。空样本返回全零。"""
    counts = [0] * (len(edges) + 1)
    for v in vals:
        counts[bisect_left(edges, v)] += 1
    n = len(vals)
    return [c / n for c in counts] if n else [0.0] * len(counts)


def _merge_small_bins(expected: List[float], actual: List[float],
                      min_frac: float) -> Tuple[List[float], List[float]]:
    """expected 占比 < min_frac 的箱向后并;末箱过小则并回前箱。
    合并以 expected 为准 —— 基准里就没人的箱,不配单独参与打分。"""
    me, ma = [], []
    acc_e = acc_a = 0.0
    for e, a in zip(expected, actual):
        acc_e += e
        acc_a += a
        if acc_e >= min_frac:
            me.append(acc_e)
            ma.append(acc_a)
            acc_e = acc_a = 0.0
    if acc_e or acc_a:
        if me:
            me[-1] += acc_e
            ma[-1] += acc_a
        else:
            me.append(acc_e)
            ma.append(acc_a)
    return me, ma


def numeric_psi(expected_vals: Sequence[float], actual_vals: Sequence[float],
                n_bins: int = 5, min_bin_frac: float = 0.05,
                include_missing: bool = False,
                expected_missing: int = 0, actual_missing: int = 0) -> Optional[float]:
    """数值特征 PSI。切点取自基准分布(等频),缺失箱默认不参与(模块
    docstring 的口径约定)。基准为常数或任一侧样本不足时返回 None。"""
    if min(len(expected_vals), len(actual_vals)) < MIN_PSI_SAMPLES:
        return None
    edges = _quantile_edges(expected_vals, n_bins)
    if not edges:
        return None
    ef = _bin_fracs(expected_vals, edges)
    af = _bin_fracs(actual_vals, edges)
    ef, af = _merge_small_bins(ef, af, min_bin_frac)
    if include_missing:
        en = len(expected_vals) + expected_missing
        an = len(actual_vals) + actual_missing
        ef = [f * len(expected_vals) / en for f in ef] + [expected_missing / en]
        af = [f * len(actual_vals) / an for f in af] + [actual_missing / an]
    return _psi(ef, af)


def categorical_psi(expected: Counter, actual: Counter,
                    top_k: int = 8) -> Optional[float]:
    """类别特征 PSI:基准期 Top-K 类 + Other。任一侧样本不足返回 None。"""
    en, an = sum(expected.values()), sum(actual.values())
    if min(en, an) < MIN_PSI_SAMPLES:
        return None
    cats = [c for c, _ in expected.most_common(top_k)]
    ef = [expected[c] / en for c in cats]
    af = [actual[c] / an for c in cats]
    ef.append(max(0.0, 1 - sum(ef)))  # Other
    af.append(max(0.0, 1 - sum(af)))
    return _psi(ef, af)


def psi_against_edges(edges: Sequence[float], actual_vals: Sequence[float],
                      expected_n: Optional[int] = None) -> Optional[float]:
    """当前分布 vs 历史快照切点的 PSI。切点来自快照期的等频分箱,expected
    占比由切点重数还原(重复切点 = 快照大量取值恰在该点,其占比要归并到
    以该点为上界的箱)—— 快照只需存 9 个数,不必存原始样本。calibrate 的
    漂移检查用它替代单点 P99 比对:P99 只看尾部一个点,中段的整体位移
    (温水煮青蛙式养基线)只有分布级比较才看得见。
    expected_n 传快照期样本量:任一侧样本不足 MIN_PSI_SAMPLES 返回 None
    (调用方回退到 P99 单点口径 —— 小样本上分位切点本身就没统计意义)。"""
    edges = sorted(edges)
    if not edges or not actual_vals:
        return None
    if len(actual_vals) < MIN_PSI_SAMPLES:
        return None
    if expected_n is not None and expected_n < MIN_PSI_SAMPLES:
        return None
    n = len(edges) + 1  # 原始等频箱数,每箱 1/n 质量
    uniq = sorted(set(edges))
    # rank(u) = 快照中 <= u 的质量份额;unique 箱占比 = 相邻 rank 之差
    rank = {u: (len(edges) - list(reversed(edges)).index(u)) / n for u in uniq}
    ef, prev = [], 0.0
    for u in uniq:
        ef.append(rank[u] - prev)
        prev = rank[u]
    ef.append(1.0 - prev)
    af = _bin_fracs(actual_vals, uniq)
    return _psi(ef, af)


def psi_level(psi: Optional[float]) -> str:
    if psi is None:
        return "n/a"
    if psi > PSI_ALARM:
        return "alarm"
    if psi > PSI_WATCH:
        return "watch"
    return "stable"


# ---------------------------------------------------------------------------
# 分桶画像
# ---------------------------------------------------------------------------

_GRAIN = {"hour": ("%Y-%m-%d %H:00", 3600), "day": ("%Y-%m-%d", 86400)}


def _bucket_label(ts: float, grain: str) -> str:
    return time.strftime(_GRAIN[grain][0], time.gmtime(ts))


def _bucket_account_features(evs: List[Dict]) -> List[Dict]:
    """桶内逐账号特征。只用桶内事件 —— 画像看的是"这段时间的行为分布",
    混入历史会把漂移抹平。缺失语义:min_gap 单事件无间隔、amount 无订单,
    都记 None 而非 0(0 是"从未间隔 0 秒",与"没有间隔"完全两回事)。"""
    by_uid: Dict[str, List[Dict]] = defaultdict(list)
    for e in evs:
        by_uid[e["uid"]].append(e)
    out = []
    for uid, mine in by_uid.items():
        ts = sorted(e["ts"] for e in mine)
        gaps = [b - a for a, b in zip(ts, ts[1:])]
        amounts = [e["amount"] for e in mine
                   if e["type"] == "order" and e.get("amount") is not None]
        out.append({
            "event_count": len(mine),
            "distinct_ip": len({e["ip"] for e in mine}),
            "distinct_device": len({e["device_id"] for e in mine}),
            "coupon_claims": sum(1 for e in mine if e["type"] == "coupon_claim"),
            "min_gap_seconds": min(gaps) if gaps else None,
            "order_amount_max": max(amounts) if amounts else None,
        })
    return out


@tool(
    name="feature_drift",
    description=(
        "特征漂移画像:按时间粒度(day/hour)把事件流分桶,逐桶计算账号级特征的"
        "质量(样本数/缺失率)与统计(均值/P50),并以最早的基准桶为参照计算各桶 "
        "PSI(<0.1 稳定,0.1~0.25 关注,>0.25 告警),同时给出事件类型构成的类别 "
        "PSI。适合回答'特征/流量分布最近有没有变、从哪天开始变'。缺失默认不进 "
        "PSI(缺失率单独观察);业务缺失码(如 -999)用 missing_values 显式声明。"
        "注意:漂移告警优先怀疑伪正常流量在养基线,先查流量再谈重校准。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "time_grain": {"type": "string", "enum": ["day", "hour"],
                           "description": "分桶粒度,默认 day"},
            "features": {"type": "array", "items": {"type": "string"},
                         "description": "要画像的特征,默认全部行为特征"},
            "benchmark_buckets": {"type": "integer",
                                  "description": "作为基准(expected)的最早桶数,默认 1"},
            "psi_bins": {"type": "integer", "description": "数值 PSI 分箱数,默认 5"},
            "psi_min_bin_frac": {"type": "number",
                                 "description": "小箱合并阈值(基准占比),默认 0.05"},
            "psi_include_missing": {"type": "boolean",
                                    "description": "缺失是否计入 PSI,默认 false"},
            "missing_values": {"type": "array", "items": {"type": "number"},
                               "description": "业务缺失码列表(如 -999),命中视为缺失"},
        },
    },
)
def feature_drift(time_grain: str = "day",
                  features: Optional[List[str]] = None,
                  benchmark_buckets: int = 1,
                  psi_bins: int = 5,
                  psi_min_bin_frac: float = 0.05,
                  psi_include_missing: bool = False,
                  missing_values: Optional[List[float]] = None):
    if time_grain not in _GRAIN:
        return {"error": "time_grain 只支持 day / hour"}
    feats = list(features) if features else list(DRIFT_FEATURES)
    unknown = [f for f in feats if f not in DRIFT_FEATURES]
    if unknown:
        return {"error": "未知特征: %s,可选: %s" % (unknown, list(DRIFT_FEATURES))}
    missing_set = set(missing_values or [])

    buckets: Dict[str, List[Dict]] = defaultdict(list)
    for e in load_events():
        buckets[_bucket_label(e["ts"], time_grain)].append(e)
    labels = sorted(buckets)
    if len(labels) < 2:
        return {"found": False, "time_grain": time_grain, "bucket_count": len(labels),
                "note": "分桶后不足 2 个桶,无从比较;换更细的 time_grain 试试"}
    benchmark_buckets = max(1, min(benchmark_buckets, len(labels) - 1))
    bench_labels = labels[:benchmark_buckets]

    # 逐桶账号特征;命中业务缺失码的值归入缺失(MARS 口径:缺失码不进统计)
    def _split(rows: List[Dict], feat: str) -> Tuple[List[float], int]:
        vals, miss = [], 0
        for r in rows:
            v = r[feat]
            if v is None or v in missing_set:
                miss += 1
            else:
                vals.append(v)
        return vals, miss

    rows_by_label = {lb: _bucket_account_features(buckets[lb]) for lb in labels}
    bench_rows = [r for lb in bench_labels for r in rows_by_label[lb]]

    feature_out: Dict[str, Dict] = {}
    alarms: List[str] = []
    for feat in feats:
        bench_vals, bench_miss = _split(bench_rows, feat)
        trend, worst_psi, worst_bucket = [], None, None
        for lb in labels:
            vals, miss = _split(rows_by_label[lb], feat)
            n = len(vals) + miss
            psi = None if lb in bench_labels else numeric_psi(
                bench_vals, vals, psi_bins, psi_min_bin_frac,
                psi_include_missing, bench_miss, miss)
            if psi is not None and (worst_psi is None or psi > worst_psi):
                worst_psi, worst_bucket = psi, lb
            trend.append({
                "bucket": lb, "n": n,
                "missing_rate": round(miss / n, 4) if n else None,
                "mean": round(statistics.fmean(vals), 4) if vals else None,
                "p50": round(statistics.median(vals), 4) if vals else None,
                **({"psi": psi} if lb not in bench_labels else {"benchmark": True}),
            })
        level = psi_level(worst_psi)
        if level == "alarm":
            alarms.append("%s 在 %s PSI=%.3f(>%.2f)" % (feat, worst_bucket, worst_psi, PSI_ALARM))
        feature_out[feat] = {"worst_psi": worst_psi, "worst_bucket": worst_bucket,
                             "level": level, "trend": trend}

    # 事件类型构成:类别 PSI(Top-K + Other),看流量结构变化(如领券占比暴涨)
    bench_types = Counter(e["type"] for lb in bench_labels for e in buckets[lb])
    type_trend, worst_psi, worst_bucket = [], None, None
    for lb in labels:
        if lb in bench_labels:
            continue
        psi = categorical_psi(bench_types, Counter(e["type"] for e in buckets[lb]))
        if psi is not None and (worst_psi is None or psi > worst_psi):
            worst_psi, worst_bucket = psi, lb
        type_trend.append({"bucket": lb, "psi": psi})
    level = psi_level(worst_psi)
    if level == "alarm":
        alarms.append("event_type_mix 在 %s PSI=%.3f(>%.2f)" % (worst_bucket, worst_psi, PSI_ALARM))

    # 尾桶截断标注:末桶事件量明显偏低(不足中位桶一半)多半是"这一天还没
    # 过完",其 PSI 告警要打折看 —— 部分桶的分布天然偏轻,不是真漂移。
    med_events = statistics.median(len(buckets[lb]) for lb in labels[:-1])
    tail_partial = len(buckets[labels[-1]]) < 0.5 * med_events

    return {
        "found": True,
        "time_grain": time_grain,
        "bucket_count": len(labels),
        "benchmark_buckets": bench_labels,
        "tail_bucket_partial": tail_partial,
        **({"tail_note": "末桶 %s 事件量不足中位桶一半,可能未采集完整,"
                         "其 PSI 告警需人工复核" % labels[-1]} if tail_partial else {}),
        "buckets": [{"bucket": lb, "accounts": len(rows_by_label[lb]),
                     "events": len(buckets[lb])} for lb in labels],
        "psi_reference": "<%.1f 稳定; %.1f~%.2f 关注; >%.2f 告警" % (
            PSI_WATCH, PSI_WATCH, PSI_ALARM, PSI_ALARM),
        "features": feature_out,
        "event_type_mix": {"worst_psi": worst_psi, "worst_bucket": worst_bucket,
                           "level": level, "trend": type_trend},
        "alarm": bool(alarms),
        "alarms": alarms,
        "note": "漂移告警先查流量构成(伪正常流量养基线),不要直接重校准阈值",
    }
