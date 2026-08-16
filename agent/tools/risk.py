# -*- coding: utf-8 -*-
"""特征区分度评估工具:逐特征回答"这个特征多能分开 fraud 和 normal"。

指标是通用二分类区分度统计(信息论 + 排序统计,不带任何业务假设):
  IV    分箱后两类分布的加权对数差。回答"整体上这个特征带多少判别信息"。
  KS    两类经验分布函数的最大距离。回答"存不存在一个切点能最大程度分开两类"。
  Lift  风险最高的箱的欺诈浓度 / 全体基准浓度。回答"用这个特征圈最差的
        一档,比随机抓能好几倍" —— 直接对应"按它设阈值值不值"。

与既有工具的分工:backtest 答"规则判得准不准",drift 答"分布稳不稳",
这里答"哪个特征值得做规则/调阈值" —— 调参前先看哪个特征值钱,而不是
挨个试。缺失单独成箱参与 IV(缺失模式本身可能就有判别力,如 min_gap
缺失 = 单事件账号,多为正常);但 KS 只算非缺失值。

样本纪律与 drift 同门:任一类别有效样本 < MIN_CLASS 时指标记 n/a ——
小样本上的 IV/KS 全是噪声,宁可不给数。指标只算已标注账号,解读时
连 label_observation 一起看(未标注 = 尚未表现)。
"""
import math
from typing import Dict, List, Optional, Tuple

from . import tool
from .backtest import label_observation
from .datasource import load_events, load_labels
from .drift import _quantile_edges
from .featurelib import BASELINE_FEATURES, _all_account_features

MIN_CLASS = 10   # 每类最少有效样本,低于此不算 IV/KS/Lift

# IV 经验档位(通用二分类口径,阈值本身无业务含义,只用于排序解读)
IV_BANDS = ((0.02, "negligible"), (0.1, "weak"), (0.3, "medium"), (float("inf"), "strong"))


def _iv_level(iv: float) -> str:
    for thr, name in IV_BANDS:
        if iv < thr:
            return name
    return "strong"


def _split_by_label(feat: str, rows: List[Dict], labels: Dict[str, str]
                    ) -> Tuple[List[float], List[float], int, int]:
    """返回 (fraud 值, normal 值, fraud 缺失数, normal 缺失数),只看已标注账号。"""
    fv, nv, fm, nm = [], [], 0, 0
    for r in rows:
        lb = labels.get(r["uid"])
        if lb is None:
            continue
        v = r.get(feat)
        if v is None:
            fm, nm = (fm + 1, nm) if lb == "fraud" else (fm, nm + 1)
        elif lb == "fraud":
            fv.append(v)
        else:
            nv.append(v)
    return fv, nv, fm, nm


def _auc(fraud: List[float], normal: List[float]) -> float:
    """排序区分度(Mann-Whitney U / (nf*nn)),同值取平均秩。返回方向无关的
    0.5~1 口径(max(a, 1-a)):KS 答"最优单切点多好",AUC 答"整个排序多好"
    —— 一个特征 KS 高 AUC 平庸,说明只有一段区间有区分力,做规则比做分不亏。"""
    both = sorted((v, 1) for v in fraud) + sorted((v, 0) for v in normal)
    both.sort(key=lambda x: x[0])
    rank_sum, i = 0.0, 0
    while i < len(both):
        j = i
        while j < len(both) and both[j][0] == both[i][0]:
            j += 1
        avg_rank = (i + 1 + j) / 2  # 1-based 平均秩
        rank_sum += avg_rank * sum(1 for k in range(i, j) if both[k][1] == 1)
        i = j
    nf, nn = len(fraud), len(normal)
    a = (rank_sum - nf * (nf + 1) / 2) / (nf * nn)
    return round(max(a, 1 - a), 4)


def _ks(fraud: List[float], normal: List[float]) -> float:
    """两类经验 CDF 的最大距离(非缺失值)。CDF 只在"当前值整段走完"后才可比:
    同值段中途取差会把并列值当成先后关系,两个完全相同的分布能算出 KS=1。"""
    f, n = sorted(fraud), sorted(normal)
    ks = 0.0
    i = j = 0
    while i < len(f) or j < len(n):
        if j >= len(n):
            v = f[i]
        elif i >= len(f):
            v = n[j]
        else:
            v = min(f[i], n[j])
        while i < len(f) and f[i] == v:
            i += 1
        while j < len(n) and n[j] == v:
            j += 1
        ks = max(ks, abs(i / len(f) - j / len(n)))
    return round(ks, 4)


def _bin_counts(vals: List[float], edges: List[float]) -> List[int]:
    from bisect import bisect_left
    counts = [0] * (len(edges) + 1)
    for v in vals:
        counts[bisect_left(edges, v)] += 1
    return counts


def _bin_label(edges: List[float], idx: int, n_bins: int) -> str:
    if not edges:
        return "all"  # 常数特征:只有单箱 + 缺失箱,IV 只可能来自缺失模式
    if idx == 0:
        return "<=%g" % edges[0]
    if idx == n_bins - 1:
        return ">%g" % edges[-1]
    return "(%g, %g]" % (edges[idx - 1], edges[idx])


def _feature_risk_one(feat: str, rows: List[Dict], labels: Dict[str, str],
                      n_bins: int, include_bins: bool = False) -> Dict:
    fv, nv, fm, nm = _split_by_label(feat, rows, labels)
    nf, nn = len(fv) + fm, len(nv) + nm
    out: Dict = {
        "n_fraud": nf, "n_normal": nn,
        "missing_rate_fraud": round(fm / nf, 4) if nf else None,
        "missing_rate_normal": round(nm / nn, 4) if nn else None,
    }
    if min(len(fv), len(nv)) < MIN_CLASS:
        out.update({"iv": None, "ks": None, "lift": None, "level": "n/a",
                    "note": "任一类有效样本 < %d,指标不可信,不给数" % MIN_CLASS})
        return out

    # 分箱:全体非缺失值等频切点;缺失单独一箱参与 IV(缺失模式的判别力
    # 不能丢)。不做小箱合并 —— 与 PSI 不同,IV 的小箱贡献有 (pf-pn) 因子
    # 压着,不会独立爆表,eps 平滑足够。
    edges = _quantile_edges(fv + nv, n_bins)
    fc = _bin_counts(fv, edges) + [fm]
    nc = _bin_counts(nv, edges) + [nm]
    # Laplace 平滑(+0.5 计数)而非 eps 钳位:某箱一类计数为 0 时,钳位会让
    # 该箱贡献 ln(p/1e-4) 级别的天文 IV,平滑后零箱的惩罚随样本量合理缩放
    iv = 0.0
    best_lift, best_bin = None, None
    n_all_bins = len(fc)
    base_rate = len(fv) / (len(fv) + len(nv))
    labels_txt = [_bin_label(edges, i, len(edges) + 1) for i in range(len(edges) + 1)] + ["missing"]
    bins_detail = []
    for i, (f, n) in enumerate(zip(fc, nc)):
        pf = (f + 0.5) / (nf + 0.5 * n_all_bins)
        pn = (n + 0.5) / (nn + 0.5 * n_all_bins)
        iv += (pf - pn) * math.log(pf / pn)
        rate = f / (f + n) if f + n else None
        if f + n >= max(5, 0.05 * (nf + nn)):  # 太小的箱不参与 lift 评选
            lift = rate / base_rate if base_rate else None
            if lift is not None and (best_lift is None or lift > best_lift):
                best_lift, best_bin = lift, labels_txt[i]
        if include_bins and (f + n or labels_txt[i] == "missing" and (fm or nm)):
            # 分箱明细:逐箱看风险在哪一段,
            # WOE 符号即方向,阈值应该切在 WOE 变号/跳变的地方
            bins_detail.append({
                "bin": labels_txt[i], "n": f + n,
                "share": round((f + n) / (nf + nn), 4),
                "fraud_rate": round(rate, 4) if rate is not None else None,
                "woe": round(math.log(pf / pn), 3),
                "lift": round(rate / base_rate, 2) if rate is not None and base_rate else None,
            })
    # 风险方向:首末箱欺诈率对比(粗粒度,非单调时标注)
    first_rate = fc[0] / max(fc[0] + nc[0], 1)
    last_idx = len(edges)
    last_rate = fc[last_idx] / max(fc[last_idx] + nc[last_idx], 1)
    direction = "high" if last_rate > first_rate * 1.2 else (
        "low" if first_rate > last_rate * 1.2 else "nonmonotonic")

    out.update({
        "iv": round(iv, 4),
        "ks": _ks(fv, nv),
        "auc": _auc(fv, nv),
        "lift": round(best_lift, 2) if best_lift is not None else None,
        "lift_bin": best_bin,
        "risk_direction": direction,
        "level": _iv_level(iv),
        **({"bins": bins_detail} if include_bins else {}),
    })
    return out


IV_DECAY_RATIO = 0.5  # 末桶有效 IV 跌破历史最高的一半即报衰减


def _risk_trend(feats: List[str], labels: Dict[str, str],
                time_grain: str, n_bins: int) -> Optional[Dict]:
    """逐时间桶的欺诈率与特征 IV(风险趋势,转译到
    电商风控语义):区分度衰减 = 对手在适应这个特征,比整体指标掉得早。
    桶内任一类样本不足时该桶 IV 记 null(小样本纪律,同全局口径)。"""
    from .drift import _bucket_account_features, _bucket_events, _tail_partial
    buckets = _bucket_events(time_grain)
    bucket_labels = sorted(buckets)
    if len(bucket_labels) < 2:
        return None
    fraud_rates, n_labeled, iv_by_feat = [], [], {f: [] for f in feats}
    for lb in bucket_labels:
        rows = _bucket_account_features(buckets[lb])
        labeled = [r for r in rows if r["uid"] in labels]
        n_labeled.append(len(labeled))
        fraud = sum(1 for r in labeled if labels[r["uid"]] == "fraud")
        fraud_rates.append(round(fraud / len(labeled), 4) if labeled else None)
        for f in feats:
            iv_by_feat[f].append(_feature_risk_one(f, rows, labels, n_bins)["iv"])
    decay_alarms = []
    for f, ivs in iv_by_feat.items():
        valid = [(i, v) for i, v in enumerate(ivs) if v is not None]
        if len(valid) >= 3:
            peak = max(v for _, v in valid)
            last = valid[-1][1]
            if peak >= 0.1 and last < IV_DECAY_RATIO * peak:
                decay_alarms.append("%s 区分度衰减:IV 峰值 %.2f -> 末桶 %.2f,"
                                    "对手可能在适应该特征" % (f, peak, last))
    # 全桶 null 的特征不占数组(桶内样本不足以算它),只留名字
    insufficient = sorted(f for f, ivs in iv_by_feat.items()
                          if all(v is None for v in ivs))
    return {
        "buckets": bucket_labels,
        "n_labeled": n_labeled,
        "fraud_rate": fraud_rates,
        "iv": {f: ivs for f, ivs in iv_by_feat.items() if f not in insufficient},
        **({"iv_insufficient": insufficient} if insufficient else {}),
        "tail_bucket_partial": _tail_partial(buckets, bucket_labels),
        "decay_alarms": decay_alarms,
        "note": "数组与 buckets 对齐;IV 为 null 的桶是样本不足。欺诈率分母是"
                "桶内已标注账号,受标注节奏影响,连 label_observation 一起看",
    }


@tool(
    name="feature_risk",
    description=(
        "特征区分度评估:逐特征算 IV/KS/AUC/Lift 与风险方向,按 IV 排名。"
        "include_bins 附逐箱明细(欺诈率/WOE/Lift,阈值切在 WOE 跳变处);"
        "time_grain 附逐桶欺诈率与 IV 趋势,IV 跌破峰值一半报区分度衰减"
        "(对手在适应)。只算已标注账号,类样本 <10 记 n/a。"
        "只答'哪个特征值钱/IV/KS''阈值切哪''特征还灵不灵';"
        "试穿/候选新规则不要先调本工具,入口是 rule_draft_test。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "features": {"type": "array", "items": {"type": "string"},
                         "description": "要评估的特征,默认全部行为特征"},
            "n_bins": {"type": "integer", "description": "IV 分箱数,默认 5"},
            "include_bins": {"type": "boolean", "description": "附逐箱明细表,默认 false"},
            "time_grain": {"type": "string", "enum": ["day", "hour"],
                           "description": "可选:按此粒度附风险趋势与衰减检测"},
        },
    },
)
def feature_risk(features: Optional[List[str]] = None, n_bins: int = 5,
                 include_bins: bool = False, time_grain: Optional[str] = None):
    feats = list(features) if features else list(BASELINE_FEATURES)
    unknown = [f for f in feats if f not in BASELINE_FEATURES]
    if unknown:
        return {"error": "未知特征: %s,可选: %s" % (unknown, list(BASELINE_FEATURES))}
    if time_grain is not None and time_grain not in ("day", "hour"):
        return {"error": "time_grain 只支持 day / hour"}
    raw_labels = load_labels()
    labels = {u: v["label"] for u, v in raw_labels.items()}
    rows = _all_account_features()
    per_feature = {f: _feature_risk_one(f, rows, labels, n_bins, include_bins)
                   for f in feats}
    ranking = sorted((f for f in feats if per_feature[f]["iv"] is not None),
                     key=lambda f: -per_feature[f]["iv"])
    trend = _risk_trend(feats, labels, time_grain, n_bins) if time_grain else None
    return {
        "ranking_by_iv": ranking,
        "features": per_feature,
        **({"risk_trend": trend,
            "decay_alarm": bool(trend and trend["decay_alarms"])} if time_grain else {}),
        "label_observation": label_observation(raw_labels, load_events()),
        "iv_reference": "<0.02 无区分; 0.02~0.1 弱; 0.1~0.3 中; >0.3 强(经验档位,只用于排序解读)",
        "note": "指标只反映已标注账号;IV 高说明值得做规则/调阈值,方向看 risk_direction",
    }
