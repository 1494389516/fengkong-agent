"""Deterministic, auditable reranking for the small risk-knowledge corpus.

This is intentionally not a semantic-entailment model. It reorders retrieved
candidates using domain metadata and query intent, and exposes score components
for evaluation/debugging.
"""
import re
from .store import tokens

_CAVEAT_TERMS = ("误报", "合法", "正常", "边界", "不能", "能否证明", "能否确认",
                 "能否直接", "是否直接", "是否代表", "直接代表", "假阳性",
                 "false positive", "caveat", "legitimate")
_IMPL_TERMS = ("实现", "代码", "源码", "方法", "采集", "检查", "信号", "implementation",
               "source", "method", "detect")


def _contains_any(text, terms):
    value = text.casefold()
    return any(term.casefold() in value for term in terms)


def rerank(query, candidates, base_scores):
    """Return [(index, final_score, components)] in descending order."""
    q_tokens = set(tokens(query))
    caveat_intent = _contains_any(query, _CAVEAT_TERMS)
    implementation_intent = _contains_any(query, _IMPL_TERMS)
    ranked = []
    for index in candidates:
        row = candidates[index]
        title_tokens = set(tokens(row.get("title", "")))
        section_tokens = set(tokens(row.get("section", "")))
        detector_tokens = set()
        for detector in row.get("detector_ids", []):
            detector_tokens.update(tokens(detector))
        exact_detector = any(
            detector.casefold() in query.casefold()
            for detector in row.get("detector_ids", [])
            if detector
        )
        title_overlap = len(q_tokens & title_tokens) / max(1, len(q_tokens))
        section_overlap = len(q_tokens & section_tokens) / max(1, len(q_tokens))
        detector_overlap = len(q_tokens & detector_tokens) / max(1, len(q_tokens))
        heading = row.get("section", "")
        caveat_match = (1.0 if caveat_intent and _contains_any(heading, ("误报", "边界"))
                         else 0.35 if caveat_intent and _contains_any(heading, ("补充验证",))
                         else 0.0)
        implementation_match = 1.0 if implementation_intent and _contains_any(heading, ("实现", "信号")) else 0.0
        bonus = (
            (0.020 if exact_detector else 0.0)
            + 0.010 * detector_overlap
            + 0.006 * title_overlap
            + 0.004 * section_overlap
            + 0.008 * caveat_match
            + 0.006 * implementation_match
        )
        base = float(base_scores.get(index, 0.0))
        components = {
            "base": round(base, 6),
            "exact_detector": exact_detector,
            "detector_overlap": round(detector_overlap, 4),
            "title_overlap": round(title_overlap, 4),
            "section_overlap": round(section_overlap, 4),
            "caveat_intent_match": bool(caveat_match),
            "implementation_intent_match": bool(implementation_match),
            "bonus": round(bonus, 6),
        }
        ranked.append((index, base + bonus, components))
    return sorted(ranked, key=lambda item: (-item[1], candidates[item[0]]["chunk_id"]))
