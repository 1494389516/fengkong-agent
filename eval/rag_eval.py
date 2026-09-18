"""Offline retrieval checks. This does NOT measure fraud detection or LLM quality.

python -m eval.rag_eval [--hybrid] [--corpus knowledge]
Uses a temporary dataset and never replaces a production knowledge index.
"""
import argparse
import json
import os
import tempfile
import time
from pathlib import Path
from unittest.mock import patch
from agent.rag.store import ingest, search


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hybrid',action='store_true')
    parser.add_argument('--corpus',default='knowledge')
    parser.add_argument('--cases',default='eval/rag/cases.jsonl')
    args=parser.parse_args()
    cases=[json.loads(line) for line in Path(args.cases).read_text().splitlines() if line.strip()]
    provider=None
    if args.hybrid:
        from agent.rag.embeddings import configured_embedder
        provider=configured_embedder()
        if provider is None:
            parser.error('--hybrid requires explicitly configured embeddings')
    results=[]
    with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ,{'FK_DATA_DIR':directory}):
        built=ingest(args.corpus,provider)
        for case in cases:
            started=time.perf_counter()
            result=search(case['query'],platform=case['platform'],top_k=5,embedder=provider)
            found=list(dict.fromkeys(h['knowledge_id'] for h in result['hits']))
            expected=case['expected_knowledge_id']
            passed=(expected in found) if expected else not found
            results.append({'query':case['query'],'expected':expected,'found':found,'passed':passed,
                'mode':result['mode'],'warning':result['warning'],
                'latency_ms':round((time.perf_counter()-started)*1000,3)})
    positives=[r for r in results if r['expected']]
    negatives=[r for r in results if not r['expected']]
    summary={'fixture_kind':'synthetic retrieval queries; not real incident validation',
       'index':built,'total':len(results),'passed':sum(r['passed'] for r in results),
       'positive_hit_at_5':sum(r['passed'] for r in positives)/len(positives) if positives else None,
       'negative_correct_empty':sum(r['passed'] for r in negatives),
       'negative_total':len(negatives),'results':results}
    print(json.dumps(summary,ensure_ascii=False,indent=2))
    return 0 if all(r['passed'] for r in results) else 1


if __name__=='__main__':
    raise SystemExit(main())
