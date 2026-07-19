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


def _ks(fraud: List[float], normal: List[float]) -> float:
    """两类经验 CDF 的最大距离(非缺失值)。"""
    f, n = sorted(fraud), sorted(normal)
    ks = 0.0
    i = j = 0
    while i < len(f) or j < len(n):
        if j >= len(n) or (i < len(f) and f[i] <= n[j]):
            i += 1
        else:
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
                      n_bins: int) -> Dict:
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
    for i, (f, n) in enumerate(zip(fc, nc)):
        pf = (f + 0.5) / (nf + 0.5 * n_all_bins)
        pn = (n + 0.5) / (nn + 0.5 * n_all_bins)
        iv += (pf - pn) * math.log(pf / pn)
        if f + n >= max(5, 0.05 * (nf + nn)):  # 太小的箱不参与 lift 评选
            rate = f / (f + n)
            lift = rate / base_rate if base_rate else None
            if lift is not None and (best_lift is None or lift > best_lift):
                best_lift, best_bin = lift, labels_txt[i]
    # 风险方向:首末箱欺诈率对比(粗粒度,非单调时标注)
    first_rate = fc[0] / max(fc[0] + nc[0], 1)
    last_idx = len(edges)
    last_rate = fc[last_idx] / max(fc[last_idx] + nc[last_idx], 1)
    direction = "high" if last_rate > first_rate * 1.2 else (
        "low" if first_rate > last_rate * 1.2 else "nonmonotonic")

    out.update({
        "iv": round(iv, 4),
        "ks": _ks(fv, nv),
        "lift": round(best_lift, 2) if best_lift is not None else None,
        "lift_bin": best_bin,
        "risk_direction": direction,
        "level": _iv_level(iv),
    })
    return out


@tool(
    name="feature_risk",
    description=(
        "特征区分度评估:对行为特征逐个计算 IV(整体判别信息)、KS(最优切点"
        "分离度)、Lift(最差箱欺诈浓度/基准,即'按它圈人比随机好几倍')与风险"
        "方向,按 IV 排名。只算已标注账号,任一类样本 <10 记 n/a。适合'哪个"
        "特征最能区分欺诈''调阈值该从哪个特征入手'—— 调参前先看哪个特征值钱。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "features": {"type": "array", "items": {"type": "string"},
                         "description": "要评估的特征,默认全部行为特征"},
            "n_bins": {"type": "integer", "description": "IV 分箱数,默认 5"},
        },
    },
)
def feature_risk(features: Optional[List[str]] = None, n_bins: int = 5):
    feats = list(features) if features else list(BASELINE_FEATURES)
    unknown = [f for f in feats if f not in BASELINE_FEATURES]
    if unknown:
        return {"error": "未知特征: %s,可选: %s" % (unknown, list(BASELINE_FEATURES))}
    raw_labels = load_labels()
    labels = {u: v["label"] for u, v in raw_labels.items()}
    rows = _all_account_features()
    per_feature = {f: _feature_risk_one(f, rows, labels, n_bins) for f in feats}
    ranking = sorted((f for f in feats if per_feature[f]["iv"] is not None),
                     key=lambda f: -per_feature[f]["iv"])
    return {
        "ranking_by_iv": ranking,
        "features": per_feature,
        "label_observation": label_observation(raw_labels, load_events()),
        "iv_reference": "<0.02 无区分; 0.02~0.1 弱; 0.1~0.3 中; >0.3 强(经验档位,只用于排序解读)",
        "note": "指标只反映已标注账号;IV 高说明值得做规则/调阈值,方向看 risk_direction",
    }
