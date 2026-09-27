"""Compare deterministic RAG baseline with an explicitly configured CrossEncoder.

Example:
  FK_RAG_RERANK_ENABLED=1 FK_RAG_RERANK_MODEL=/models/bge-reranker-v2-m3 \
    python -m eval.rag_reranker_compare --gate-no-regression

The model is local-files-only unless FK_RAG_RERANK_ALLOW_DOWNLOAD=1.
"""
import argparse
import json
import os
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

from agent.rag.cross_encoder import configured_reranker
from agent.rag.store import ingest, search


def load_cases():
    rows = []
    for path in ("eval/rag/cases.jsonl", "eval/rag/hard_cases.jsonl"):
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            if line.strip():
                rows.append(json.loads(line))
    return rows


def run(cases, reranker=None):
    rows = []
    for case in cases:
        started = time.perf_counter()
        result = search(case["query"], platform=case["platform"], top_k=5, reranker=reranker)
        elapsed = (time.perf_counter() - started) * 1000
        expected = case["expected_knowledge_id"]
        rank = None
        if expected:
            rank = next((i + 1 for i, h in enumerate(result["hits"])
                         if h["knowledge_id"] == expected), None)
        section_ok = None
        if expected and case.get("expected_section"):
            section_ok = bool(result["hits"] and
                              result["hits"][0]["knowledge_id"] == expected and
                              result["hits"][0]["section"] == case["expected_section"])
        rows.append(dict(expected=expected, rank=rank, section_ok=section_ok,
                         negative_empty=(not result["hits"]) if expected is None else None,
                         latency_ms=elapsed))
    positives = [r for r in rows if r["expected"]]
    negatives = [r for r in rows if r["expected"] is None]
    hard = [r for r in rows if r["section_ok"] is not None]
    mean = lambda xs: sum(xs) / len(xs) if xs else None
    return {
        "hit_at_1": mean([r["rank"] == 1 for r in positives]),
        "hit_at_5": mean([r["rank"] is not None and r["rank"] <= 5 for r in positives]),
        "mrr_at_5": mean([1 / r["rank"] if r["rank"] and r["rank"] <= 5 else 0 for r in positives]),
        "negative_rejection_rate": mean([r["negative_empty"] for r in negatives]),
        "hard_section_top1": mean([r["section_ok"] for r in hard]),
        "mean_latency_ms": round(mean([r["latency_ms"] for r in rows]), 3),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gate-no-regression", action="store_true")
    args = parser.parse_args()
    reranker = configured_reranker()
    if reranker is None:
        parser.error("set FK_RAG_RERANK_ENABLED=1 and FK_RAG_RERANK_MODEL")
    cases = load_cases()
    with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"FK_DATA_DIR": directory}):
        ingest("knowledge")
        baseline = run(cases)
        candidate = run(cases, reranker)
    quality = ("hit_at_1", "hit_at_5", "mrr_at_5",
               "negative_rejection_rate", "hard_section_top1")
    delta = {key: round(candidate[key] - baseline[key], 6) for key in quality}
    result = {
        "fixture_kind": "synthetic before/after reranker comparison; not incident validation",
        "reranker": reranker.identity,
        "baseline": baseline,
        "candidate": candidate,
        "quality_delta": delta,
        "latency_delta_ms": round(candidate["mean_latency_ms"] - baseline["mean_latency_ms"], 3),
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if args.gate_no_regression and any(candidate[k] < baseline[k] for k in quality):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
