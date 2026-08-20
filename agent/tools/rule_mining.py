# -*- coding: utf-8 -*-
"""候选规则挖掘:在时间切分训练侧发现规则,只在更晚评估侧复验。

本模块属于 Agent Plane 的 simulate 工具,只生成结构化候选,不注册策略、
不修改阈值、更不进入在线判定。候选排序只使用训练侧指标;评估侧只报告
泛化表现,避免把 holdout 再次用作搜索集。
"""
import math
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from . import tool
from .dataset import MODELING_COLUMNS, feature_rows, split_datasets
from .draft import DRAFT_FEATURES

DEFAULT_QUANTILES = (0.05, 0.10, 0.20, 0.50, 0.80, 0.90, 0.95)
AST_VERSION = "rule-ast/v1"


def _number(value) -> Optional[float]:
    if value in (None, "") or isinstance(value, bool):
        return None
    try:
        out = float(value)
    except (TypeError, ValueError):
        return None
    return out if math.isfinite(out) else None


def _quantile(values: Sequence[float], q: float) -> float:
    """线性插值分位点,与外部数值库无关且同输入确定性。"""
    ordered = sorted(values)
    if not ordered:
        raise ValueError("空序列没有分位点")
    pos = (len(ordered) - 1) * q
    lo = int(math.floor(pos))
    hi = int(math.ceil(pos))
    if lo == hi:
        return ordered[lo]
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (pos - lo)


def _matches(row: Dict, ast: Dict) -> bool:
    value = _number(row.get(ast["feature"]))
    op = ast["operator"]
    if op == "is_null":
        return value is None
    if value is None:
        return False
    threshold = float(ast["value"])
    if op == "lte":
        return value <= threshold
    if op == "gte":
        return value >= threshold
    raise ValueError("不支持的规则算子: %s" % op)


def _draft_condition(ast: Dict) -> Optional[Dict]:
    """转换成 rule_draft_test 可直接消费的单条件;缺失规则尚不在试衣间算子集。"""
    op = {"lte": "<=", "gte": ">="}.get(ast["operator"])
    if op is None or ast["feature"] not in DRAFT_FEATURES:
        return None
    return {"feature": ast["feature"], "op": op, "value": ast["value"]}


def evaluate_rule(rows: Sequence[Dict], ast: Dict) -> Dict:
    """在给定样本上计算二分类规则指标;fraud 为正类。"""
    tp = fp = fn = tn = 0
    for row in rows:
        positive = row.get("label") == "fraud"
        hit = _matches(row, ast)
        if hit and positive:
            tp += 1
        elif hit:
            fp += 1
        elif positive:
            fn += 1
        else:
            tn += 1
    n = len(rows)
    hits = tp + fp
    positives = tp + fn
    precision = tp / hits if hits else 0.0
    recall = tp / positives if positives else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    base_rate = positives / n if n else 0.0
    return {
        "rows": n,
        "hits": hits,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "support": round(hits / n, 4) if n else 0.0,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "lift": round(precision / base_rate, 4) if base_rate else 0.0,
        "base_rate": round(base_rate, 4),
    }


def _candidate_asts(rows: Sequence[Dict], features: Iterable[str],
                    quantiles: Sequence[float], min_support: float) -> List[Dict]:
    candidates: List[Dict] = []
    seen: set = set()
    for feature in features:
        values = [_number(row.get(feature)) for row in rows]
        numeric = [v for v in values if v is not None]
        for q in quantiles:
            if not numeric:
                break
            threshold = round(_quantile(numeric, q), 8)
            for op in ("lte", "gte"):
                key = (feature, op, threshold)
                if key in seen:
                    continue
                seen.add(key)
                candidates.append({
                    "version": AST_VERSION,
                    "feature": feature,
                    "operator": op,
                    "value": threshold,
                })
        missing_rate = sum(v is None for v in values) / len(values) if values else 0.0
        if missing_rate >= min_support:
            candidates.append({
                "version": AST_VERSION,
                "feature": feature,
                "operator": "is_null",
                "value": None,
            })
    return candidates


def discover_candidates(train_rows: Sequence[Dict], eval_rows: Sequence[Dict],
                        *, features: Iterable[str] = MODELING_COLUMNS,
                        quantiles: Sequence[float] = DEFAULT_QUANTILES,
                        min_support: float = 0.03, min_lift: float = 1.05,
                        max_hit_rate: float = 0.70,
                        max_candidates: int = 5) -> List[Dict]:
    """只按训练侧过滤与排序,随后附加独立评估侧指标。"""
    ranked: List[Tuple[Tuple[float, float, float], Dict]] = []
    for ast in _candidate_asts(train_rows, features, quantiles, min_support):
        train = evaluate_rule(train_rows, ast)
        if (train["support"] < min_support
                or train["support"] > max_hit_rate
                or train["lift"] < min_lift):
            continue
        expression = ("%s is null" % ast["feature"] if ast["operator"] == "is_null"
                      else "%s %s %s" % (
                          ast["feature"],
                          "<=" if ast["operator"] == "lte" else ">=",
                          ast["value"]))
        item = {
            "candidate_id": "",
            "ast": ast,
            "expression": expression,
            "train": train,
        }
        condition = _draft_condition(ast)
        item["draft_compatible"] = condition is not None
        if condition is not None:
            item["conditions"] = [condition]
        ranked.append(((train["f1"], train["lift"], train["recall"]), item))
    ranked.sort(key=lambda pair: pair[0], reverse=True)

    out: List[Dict] = []
    for index, (_, item) in enumerate(ranked[:max_candidates], 1):
        validation = evaluate_rule(eval_rows, item["ast"])
        item["candidate_id"] = "C%03d" % index
        item["validation"] = validation
        item["stability"] = {
            "lift_above_random": validation["lift"] >= 1.0,
            "support_delta": round(validation["support"] - item["train"]["support"], 4),
            "f1_gap": round(validation["f1"] - item["train"]["f1"], 4),
        }
        out.append(item)
    return out


def mine_rules(split_ratio: float = 0.7, min_support: float = 0.03,
               min_lift: float = 1.05, max_candidates: int = 5) -> Dict:
    if not 0.5 <= split_ratio <= 0.9:
        return {"error": "split_ratio 必须在 0.5~0.9,保证训练/评估两侧都有意义"}
    if not 0.0 < min_support < 0.5:
        return {"error": "min_support 必须在 0~0.5"}
    if not 1.0 <= min_lift <= 20.0:
        return {"error": "min_lift 必须在 1~20"}
    if not 1 <= max_candidates <= 5:
        return {"error": "max_candidates 必须在 1~5,防止候选明细突破单工具上下文预算"}

    split = split_datasets(split_ratio)
    if "error" in split:
        return split
    train_rows, train_skipped = feature_rows(split["train_accounts"])
    eval_rows, eval_skipped = feature_rows(split["eval_accounts"])
    if not train_rows or not eval_rows:
        return {"error": "时间切分后训练或评估特征为空,无法挖掘"}
    train_counts = {
        label: sum(row.get("label") == label for row in train_rows)
        for label in ("fraud", "normal")
    }
    eval_counts = {
        label: sum(row.get("label") == label for row in eval_rows)
        for label in ("fraud", "normal")
    }
    if not all(train_counts.values()) or not all(eval_counts.values()):
        return {
            "error": (
                "训练与验证两侧都必须同时包含 fraud/normal;当前 train=%s,"
                "validation=%s。请扩充标签样本,不能在单类别 holdout 上报告泛化指标"
                % (train_counts, eval_counts)
            ),
            "train_label_counts": train_counts,
            "validation_label_counts": eval_counts,
        }

    candidates = discover_candidates(
        train_rows,
        eval_rows,
        min_support=min_support,
        min_lift=min_lift,
        max_candidates=max_candidates,
    )
    return {
        "mode": "candidate_discovery_only",
        "selection_policy": "候选生成、过滤、排序仅使用 train;validation 只复验不参与选优",
        "split": {
            "ratio": split_ratio,
            "cutoff_ts": split["cutoff_ts"],
            "train_rows": len(train_rows),
            "validation_rows": len(eval_rows),
            "train_label_counts": train_counts,
            "validation_label_counts": eval_counts,
            "train_fingerprint": split["train_fingerprint"],
            "validation_fingerprint": split["eval_fingerprint"],
            "disjoint": split["disjoint"],
            "skipped": {"train": train_skipped, "validation": eval_skipped},
        },
        "search": {
            "features": list(MODELING_COLUMNS),
            "quantiles": list(DEFAULT_QUANTILES),
            "operators": ["lte", "gte", "is_null"],
            "combination": "none",
            "min_support": min_support,
            "min_lift": min_lift,
            "max_candidates": max_candidates,
        },
        "candidate_count": len(candidates),
        "candidates": candidates,
        "next_gate": (
            "候选尚未注册或生效;先检查 validation 稳定性与业务误伤成本,"
            "draft_compatible=true 时可把 conditions 原样传给 rule_draft_test,"
            "再经 strategy_shadow 复验并进入人工审批"
        ),
    }


@tool(
    name="rule_mining",
    description=(
        "从现有标签与 point-in-time 特征中自动发现候选规则。强制按账号最后事件时间"
        "切分 train/validation:阈值生成、过滤和排序只看 train,更晚 validation 只做"
        "独立复验。返回 rule-ast/v1 结构化候选、两侧指纹与 P/R/F1/Lift,不写策略、"
        "不改阈值、不进入在线判定。draft_compatible 候选的 conditions 可直接传给"
        "rule_draft_test;候选上线前仍须业务成本评估、影子回放和人工审批。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "split_ratio": {
                "type": "number",
                "description": "训练侧占比,0.5~0.9,默认 0.7",
            },
            "min_support": {
                "type": "number",
                "description": "训练侧最小命中率,0~0.5,默认 0.03",
            },
            "min_lift": {
                "type": "number",
                "description": "训练侧最小 Lift,1~20,默认 1.05",
            },
            "max_candidates": {
                "type": "integer",
                "description": "最多返回候选数,1~5,默认 5",
            },
        },
    },
)
def rule_mining(split_ratio: float = 0.7, min_support: float = 0.03,
                min_lift: float = 1.05, max_candidates: int = 5):
    return mine_rules(split_ratio, min_support, min_lift, max_candidates)
