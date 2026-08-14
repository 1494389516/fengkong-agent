#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""模型评估指标库:纯 stdlib 实现 AUC/KS/Precision@K/Recall/FPR/FNR/混淆矩阵。

不依赖 sklearn(骨架纪律:stdlib 优先);分值为风险分(越大越可疑),
标签为 fraud/normal。所有指标确定性可复现,同一份 (scores, labels)
输入必然得到同一份输出 —— 这是模型评估进 eval 回归的前提。

约定:
- score 范围不限,仅比较序(rank-based 指标)与阈值(混淆矩阵默认 0.5);
- 样本数过少时部分指标返回 None 并注明(小样本上的 AUC 没有意义,
  诚实返回 None 而不是编一个数);
- 本模块只算数,不读写任何文件 —— 数据面由调用方(model_eval 工具/
  eval 层)负责。
"""
from typing import Dict, List, Optional, Tuple


def _pairs(scores: Dict[str, float], labels: Dict[str, str]) -> List[Tuple[float, int]]:
    """(score, y) 列表,y=1 为 fraud。未知/未标注 uid 不参与(评估口径:
    未标注不是 normal)。"""
    out = []
    for uid, s in scores.items():
        lab = labels.get(uid)
        if lab is None:
            continue
        if isinstance(lab, dict):  # datasource.load_labels 返回 {label, note} 形态
            lab = lab.get("label")
        if lab == "fraud":
            out.append((float(s), 1))
        elif lab == "normal":
            out.append((float(s), 0))
    return out


def auc(scores: Dict[str, float], labels: Dict[str, str]) -> Optional[float]:
    """rank-based AUC(Mann-Whitney U)。"""
    pairs = _pairs(scores, labels)
    n_pos = sum(1 for _, y in pairs if y == 1)
    n_neg = len(pairs) - n_pos
    if n_pos == 0 or n_neg == 0:
        return None
    ordered = sorted(pairs, key=lambda p: p[0])
    # 平局给平均秩(与 sklearn 的 average='rank' 一致)
    ranks = {}
    i = 0
    while i < len(ordered):
        j = i
        while j + 1 < len(ordered) and ordered[j + 1][0] == ordered[i][0]:
            j += 1
        avg = (i + 1 + j + 1) / 2.0
        for k in range(i, j + 1):
            ranks[k] = avg
        i = j + 1
    sum_pos = sum(ranks[k] for k, (_, y) in enumerate(ordered) if y == 1)
    return round((sum_pos - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg), 4)


def ks(scores: Dict[str, float], labels: Dict[str, str]) -> Optional[float]:
    """KS:正负样本累计分布的最大分离。"""
    pairs = _pairs(scores, labels)
    n_pos = sum(1 for _, y in pairs if y == 1)
    n_neg = len(pairs) - n_pos
    if n_pos == 0 or n_neg == 0:
        return None
    ordered = sorted(pairs, key=lambda p: p[0])
    cum_pos = cum_neg = 0.0
    best = 0.0
    for _, y in ordered:
        if y == 1:
            cum_pos += 1
        else:
            cum_neg += 1
        best = max(best, abs(cum_pos / n_pos - cum_neg / n_neg))
    return round(best, 4)


def confusion(scores: Dict[str, float], labels: Dict[str, str],
              threshold: float = 0.5) -> Dict[str, int]:
    """混淆矩阵(默认阈值 0.5):tp/fp/tn/fn。"""
    tp = fp = tn = fn = 0
    for score, y in _pairs(scores, labels):
        pred = 1 if score >= threshold else 0
        if pred == 1 and y == 1:
            tp += 1
        elif pred == 1 and y == 0:
            fp += 1
        elif pred == 0 and y == 0:
            tn += 1
        else:
            fn += 1
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def evaluate(scores: Dict[str, float], labels: Dict[str, str],
             k: Optional[int] = None, threshold: float = 0.5) -> Dict:
    """一次完整评估:全部指标 + 样本口径。返回的字典可直接进模型登记簿
    的 metrics 字段(带 sample_count,消费方据此判断可信度)。"""
    pairs = _pairs(scores, labels)
    n = len(pairs)
    n_pos = sum(1 for _, y in pairs if y == 1)
    cm = confusion(scores, labels, threshold)
    k = min(k, n) if k else min(10, n)
    top_k = sorted(pairs, key=lambda p: p[0], reverse=True)[:k]
    tp_k = sum(1 for _, y in top_k if y == 1)
    precision_k = round(tp_k / k, 4) if k else None
    recall_k = round(tp_k / n_pos, 4) if n_pos else None
    return {
        "auc": auc(scores, labels),
        "ks": ks(scores, labels),
        "precision_at_k": precision_k,
        "recall_at_k": recall_k,
        "precision": round(cm["tp"] / (cm["tp"] + cm["fp"]), 4)
        if (cm["tp"] + cm["fp"]) else None,
        "recall": round(cm["tp"] / (cm["tp"] + cm["fn"]), 4)
        if (cm["tp"] + cm["fn"]) else None,
        "fpr": round(cm["fp"] / (cm["fp"] + cm["tn"]), 4)
        if (cm["fp"] + cm["tn"]) else None,
        "fnr": round(cm["fn"] / (cm["fn"] + cm["tp"]), 4)
        if (cm["fn"] + cm["tp"]) else None,
        "confusion_matrix": cm,
        "threshold": threshold,
        "sample_count": n,
        "positives": n_pos,
        "k": k,
    }


def compare(champion_metrics: Dict, challenger_metrics: Dict) -> Dict:
    """Champion vs Challenger 指标对比表(metric/champion/challenger/delta)。
    只在两边都有值的指标上比;样本数取两者较小并注明(样本数不齐的对比
    是错觉)。"""
    rows = []
    for metric in ("auc", "ks", "precision", "recall", "fpr", "fnr",
                   "precision_at_k", "recall_at_k"):
        cv = champion_metrics.get(metric)
        gv = challenger_metrics.get(metric)
        if cv is None or gv is None:
            continue
        rows.append({"metric": metric, "champion": cv, "challenger": gv,
                     "delta": round(gv - cv, 4)})
    return {
        "rows": rows,
        "champion_sample_count": champion_metrics.get("sample_count"),
        "challenger_sample_count": challenger_metrics.get("sample_count"),
        "dataset_fingerprint": challenger_metrics.get("eval_fingerprint"),
        "note": "delta = challenger - champion;正号表示挑战者更优(按指标方向)",
    }


def champion_beats_challenger(champion_metrics: Dict, challenger_metrics: Dict,
                              min_delta: float = 0.0) -> Tuple[bool, List[str]]:
    """挑战者是否全面不劣于当前 champion(评估门禁用)。
    返回 (是否通过, 不达标指标列表)。方向:fpr/fnr 越小越好,其余越大越好。"""
    lower_better = {"fpr", "fnr"}
    failed = []
    for metric in ("auc", "ks", "precision", "recall", "fpr", "fnr"):
        cv = champion_metrics.get(metric)
        gv = challenger_metrics.get(metric)
        if cv is None or gv is None:
            continue  # 任一侧缺失该指标,不做门禁判断(诚实跳过)
        delta = gv - cv
        ok = delta <= min_delta if metric in lower_better else delta >= -min_delta
        if not ok:
            failed.append(metric)
    return (not failed, failed)
