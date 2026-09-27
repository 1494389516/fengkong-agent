# -*- coding: utf-8 -*-
"""Run the configured entailment evaluator against a labeled calibration set.

The checked-in set is explicitly simulated and is useful only as a smoke test.
Production calibration must point --cases at a reviewed, de-identified labeled
set and should pin evaluator model/revision outside this script.
"""
import argparse
import json
from pathlib import Path

from agent.rag.entailment import configured_evaluator


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--cases", default="eval/rag/entailment_cases.jsonl")
    p.add_argument("--gate", action="store_true")
    p.add_argument("--min-accuracy", type=float, default=0.85)
    args = p.parse_args()
    evaluator = configured_evaluator()
    if evaluator is None:
        raise SystemExit("FK_RAG_ENTAILMENT_ENABLED=1 and separate evaluator config required")
    rows = [json.loads(x) for x in Path(args.cases).read_text(encoding="utf-8").splitlines() if x.strip()]
    correct = 0
    by_label = {}
    for row in rows:
        got = evaluator.evaluate(row["claim"], row["premise"])["label"]
        correct += int(got == row["label"])
        bucket = by_label.setdefault(row["label"], {"n": 0, "correct": 0})
        bucket["n"] += 1
        bucket["correct"] += int(got == row["label"])
    accuracy = correct / max(1, len(rows))
    result = {"cases": len(rows), "accuracy": round(accuracy, 4),
              "per_label_recall": {k: round(v["correct"]/v["n"], 4) for k,v in by_label.items()},
              "simulated_only": all(bool(r.get("simulated")) for r in rows)}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if args.gate and accuracy < args.min_accuracy:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
