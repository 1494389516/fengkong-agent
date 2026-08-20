# -*- coding: utf-8 -*-
"""候选规则挖掘:在时间切分训练侧发现规则,只在更晚评估侧复验。

本模块属于 Agent Plane 的 simulate 工具,只生成结构化候选,不注册策略、
不修改阈值、更不进入在线判定。候选排序只使用训练侧指标;评估侧只报告
泛化表现,避免把 holdout 再次用作搜索集。
"""
import hashlib
import itertools
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from . import tool
from .datasource import atomic_write_json
from .dataset import MODELING_COLUMNS, feature_rows, split_datasets
from .draft import DRAFT_FEATURES

DEFAULT_QUANTILES = (0.05, 0.10, 0.20, 0.50, 0.80, 0.90, 0.95)
AST_VERSION = "rule-ast/v1"
COMBO_AST_VERSION = "rule-combo/v1"
SEARCH_POOL_SIZE = 12


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


def _evaluate(rows: Sequence[Dict], matcher) -> Dict:
    """按 matcher 计算账号级二分类指标;fraud 为正类。"""
    tp = fp = fn = tn = 0
    for row in rows:
        positive = row.get("label") == "fraud"
        hit = matcher(row)
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
    negatives = fp + tn
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
        "fpr": round(fp / negatives, 4) if negatives else 0.0,
        "fnr": round(fn / positives, 4) if positives else 0.0,
        "lift": round(precision / base_rate, 4) if base_rate else 0.0,
        "base_rate": round(base_rate, 4),
    }


def evaluate_rule(rows: Sequence[Dict], ast: Dict) -> Dict:
    return _evaluate(rows, lambda row: _matches(row, ast))


def evaluate_or(rows: Sequence[Dict], asts: Sequence[Dict]) -> Dict:
    """OR 组合:命中任一候选即命中组合。"""
    return _evaluate(rows, lambda row: any(_matches(row, ast) for ast in asts))


def _cost(metrics: Dict, fp_cost: float, fn_cost: float) -> Dict:
    total = metrics["fp"] * fp_cost + metrics["fn"] * fn_cost
    baseline = (metrics["tp"] + metrics["fn"]) * fn_cost
    return {
        "fp_cost": fp_cost,
        "fn_cost": fn_cost,
        "expected_loss": round(total, 4),
        "loss_per_row": round(total / metrics["rows"], 6) if metrics["rows"] else 0.0,
        "savings_vs_no_rule": round(baseline - total, 4),
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


def _structurally_redundant(items: Sequence[Dict]) -> bool:
    """同特征同方向的 OR 只保留一个阈值,组合它们没有新增表达能力。"""
    seen = set()
    for item in items:
        ast = item["ast"]
        key = (ast["feature"], ast["operator"])
        if key in seen:
            return True
        seen.add(key)
    return False


def search_or_combinations(train_rows: Sequence[Dict], eval_rows: Sequence[Dict],
                           candidates: Sequence[Dict], *, max_rules: int = 3,
                           fp_cost: float = 1.0, fn_cost: float = 5.0,
                           max_fpr: float = 0.10) -> Dict:
    """训练侧按成本搜索 OR 组合,验证侧只复验。

    搜索空间很小(默认 12 个候选、最多 3 条),直接穷举比启发式分支更透明。
    相同训练命中掩码只保留成本相同下规则更少的组合。
    """
    evaluated: List[Dict] = []
    seen_masks = set()
    attempted = skipped_structural = skipped_duplicate = rejected_fpr = 0
    for size in range(1, min(max_rules, len(candidates)) + 1):
        for group in itertools.combinations(candidates, size):
            attempted += 1
            if _structurally_redundant(group):
                skipped_structural += 1
                continue
            asts = [item["ast"] for item in group]
            mask = tuple(any(_matches(row, ast) for ast in asts) for row in train_rows)
            if mask in seen_masks:
                skipped_duplicate += 1
                continue
            seen_masks.add(mask)
            train = evaluate_or(train_rows, asts)
            train_cost = _cost(train, fp_cost, fn_cost)
            if train["fpr"] > max_fpr:
                rejected_fpr += 1
                continue
            validation = evaluate_or(eval_rows, asts)
            validation_cost = _cost(validation, fp_cost, fn_cost)
            combo = {
                "combo_id": "",
                "ast": {
                    "version": COMBO_AST_VERSION,
                    "logic": "or",
                    "rules": asts,
                },
                "candidate_ids": [item["candidate_id"] for item in group],
                "expressions": [item["expression"] for item in group],
                "train": train,
                "train_cost": train_cost,
                "validation": validation,
                "validation_cost": validation_cost,
                "validation_gate": {
                    "fpr_within_limit": validation["fpr"] <= max_fpr,
                    "positive_savings": validation_cost["savings_vs_no_rule"] > 0,
                    "lift_above_random": validation["lift"] >= 1.0,
                },
            }
            evaluated.append(combo)
    evaluated.sort(key=lambda item: (
        item["train_cost"]["expected_loss"],
        -item["train"]["f1"],
        len(item["candidate_ids"]),
        item["candidate_ids"],
    ))
    for index, item in enumerate(evaluated, 1):
        item["combo_id"] = "OR%03d" % index
    best = evaluated[0] if evaluated else None
    return {
        "objective": "minimize(fp*fp_cost + fn*fn_cost) on train",
        "constraints": {"max_fpr": max_fpr, "max_rules": max_rules},
        "search_diagnostics": {
            "attempted_subsets": attempted,
            "skipped_structural_redundancy": skipped_structural,
            "skipped_duplicate_train_mask": skipped_duplicate,
            "rejected_train_fpr": rejected_fpr,
        },
        "evaluated_count": len(evaluated),
        "best": best,
        "all": evaluated,
    }


def _lineage() -> Dict:
    from .dataset import dataset_fingerprint
    from .featurelib import FEATURE_CATALOG_VERSION
    from .label_lifecycle import label_fingerprint
    from .readiness import _git_commit
    from ..engine import _active_strategy

    strategy = _active_strategy()
    return {
        "dataset_fingerprint": dataset_fingerprint(),
        "label_fingerprint": label_fingerprint(),
        "feature_catalog_version": FEATURE_CATALOG_VERSION,
        "strategy_version": strategy.get("strategy_version") or "none",
        "git_commit": _git_commit() or "unknown",
    }


def _write_snapshot(body: Dict) -> Dict:
    """完整搜索旁路落盘;返回可审计引用,不把全量组合塞进 LLM 上下文。"""
    from .shadow_store import artifacts_dir

    lineage = _lineage()
    payload = {
        "kind": "rule_mining",
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        **lineage,
        **body,
    }
    blob = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
    digest = hashlib.sha256(blob.encode("utf-8")).hexdigest()
    artifact_id = digest[:16]
    payload["sha256"] = digest
    path = artifacts_dir() / ("rule_mining_%s.json" % artifact_id)
    atomic_write_json(path, payload)
    return {
        "artifact_id": artifact_id,
        "path": str(path),
        "sha256": digest,
        "single_candidates": len(body.get("candidates") or []),
        "or_combinations": len((body.get("or_search") or {}).get("all") or []),
        **lineage,
    }


def verify_snapshot(ref: Dict) -> Dict:
    """校验研究产物内容哈希;失败显式报错,不接受被改写的搜索证据。"""
    path = ref.get("path")
    expect = ref.get("sha256")
    if not path or not expect:
        return {"error": "快照引用缺 path/sha256"}
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"error": "快照不可读: %s" % exc}
    stored = payload.pop("sha256", None)
    blob = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
    actual = hashlib.sha256(blob.encode("utf-8")).hexdigest()
    if stored != expect or actual != expect:
        return {"error": "快照哈希不匹配(产物已被改写)"}
    return {"valid": True, "artifact_id": ref.get("artifact_id"),
            "sha256": actual, "body": payload}


def mine_rules(split_ratio: float = 0.7, min_support: float = 0.03,
               min_lift: float = 1.05, max_candidates: int = 2,
               max_rules: int = 3, fp_cost: float = 1.0,
               fn_cost: float = 5.0, max_fpr: float = 0.10,
               save_snapshot: bool = True) -> Dict:
    numeric = {
        "split_ratio": split_ratio,
        "min_support": min_support,
        "min_lift": min_lift,
        "fp_cost": fp_cost,
        "fn_cost": fn_cost,
        "max_fpr": max_fpr,
    }
    bad_numeric = [name for name, value in numeric.items()
                   if (not isinstance(value, (int, float))
                       or isinstance(value, bool)
                       or not math.isfinite(float(value)))]
    if bad_numeric:
        return {"error": "参数必须为有限数值: %s" % ", ".join(bad_numeric)}
    if (not isinstance(max_candidates, int) or isinstance(max_candidates, bool)
            or not isinstance(max_rules, int) or isinstance(max_rules, bool)):
        return {"error": "max_candidates/max_rules 必须为整数"}
    if not 0.5 <= split_ratio <= 0.9:
        return {"error": "split_ratio 必须在 0.5~0.9,保证训练/评估两侧都有意义"}
    if not 0.0 < min_support < 0.5:
        return {"error": "min_support 必须在 0~0.5"}
    if not 1.0 <= min_lift <= 20.0:
        return {"error": "min_lift 必须在 1~20"}
    if not 1 <= max_candidates <= 2:
        return {"error": "max_candidates 必须在 1~2;全量候选进入快照,上下文只回 top"}
    if not 1 <= max_rules <= 3:
        return {"error": "max_rules 必须在 1~3,限制 OR 搜索复杂度与规则可解释性"}
    if fp_cost < 0 or fn_cost <= 0 or (fp_cost == 0 and fn_cost == 0):
        return {"error": "fp_cost 必须 >=0 且 fn_cost 必须 >0"}
    if not 0 <= max_fpr <= 1:
        return {"error": "max_fpr 必须在 0~1"}
    if not isinstance(save_snapshot, bool):
        return {"error": "save_snapshot 必须为布尔值"}

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

    all_candidates = discover_candidates(
        train_rows,
        eval_rows,
        min_support=min_support,
        min_lift=min_lift,
        max_candidates=SEARCH_POOL_SIZE,
    )
    or_search = search_or_combinations(
        train_rows,
        eval_rows,
        all_candidates,
        max_rules=max_rules,
        fp_cost=fp_cost,
        fn_cost=fn_cost,
        max_fpr=max_fpr,
    )
    split_meta = {
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
    }
    search_meta = {
        "features": list(MODELING_COLUMNS),
        "quantiles": list(DEFAULT_QUANTILES),
        "operators": ["lte", "gte", "is_null"],
        "combination": "or",
        "min_support": min_support,
        "min_lift": min_lift,
        "max_candidates": max_candidates,
        "search_pool_size": len(all_candidates),
        "max_rules": max_rules,
        "fp_cost": fp_cost,
        "fn_cost": fn_cost,
        "max_fpr": max_fpr,
    }
    snapshot = None
    if save_snapshot:
        snapshot = _write_snapshot({
            "split": split_meta,
            "search": search_meta,
            "candidates": all_candidates,
            "or_search": or_search,
        })
    return {
        "mode": "candidate_and_or_search",
        "selection_policy": (
            "单规则与 OR 组合均只在 train 生成/过滤/排序;"
            "validation 只复验,不参与选优"
        ),
        "split": split_meta,
        "search": search_meta,
        "candidate_count": len(all_candidates),
        "candidates": all_candidates[:max_candidates],
        "or_search": {
            "objective": or_search["objective"],
            "constraints": or_search["constraints"],
            "search_diagnostics": or_search["search_diagnostics"],
            "evaluated_count": or_search["evaluated_count"],
            "best": or_search["best"],
        },
        **({"artifact": snapshot} if snapshot else {}),
        "next_gate": (
            "候选与组合尚未注册或生效;先检查 validation_gate 与业务成本,"
            "draft_compatible=true 时可把 conditions 原样传给 rule_draft_test,"
            "再经 strategy_shadow 复验并进入人工审批"
        ),
    }


@tool(
    name="rule_mining",
    description=(
        "时间切分后发现单规则并穷举最多 3 条 OR 组合;只在 train 按"
        "FP×误伤成本+FN×漏放成本选优,validation 仅复验。返回 top 候选、最佳组合"
        "和带数据/标签/特征/策略指纹的完整快照引用,不改策略、不进入在线判定。"
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
                "description": "上下文最多返回单候选数,1~2,默认 2;全量进快照",
            },
            "max_rules": {
                "type": "integer",
                "description": "OR 组合最大规则数,1~3,默认 3",
            },
            "fp_cost": {
                "type": "number",
                "description": "每个误伤的相对成本,默认 1",
            },
            "fn_cost": {
                "type": "number",
                "description": "每个漏放的相对成本,默认 5",
            },
            "max_fpr": {
                "type": "number",
                "description": "训练侧允许的最大误伤率,0~1,默认 0.1",
            },
            "save_snapshot": {
                "type": "boolean",
                "description": "是否把完整搜索写入研究产物,默认 true",
            },
        },
    },
)
def rule_mining(split_ratio: float = 0.7, min_support: float = 0.03,
                min_lift: float = 1.05, max_candidates: int = 2,
                max_rules: int = 3, fp_cost: float = 1.0,
                fn_cost: float = 5.0, max_fpr: float = 0.10,
                save_snapshot: bool = True):
    return mine_rules(split_ratio, min_support, min_lift, max_candidates,
                      max_rules, fp_cost, fn_cost, max_fpr, save_snapshot)
