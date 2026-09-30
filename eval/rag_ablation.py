"""Reproducible retrieval-only ablation; never claims LLM or incident quality.

Default: checked-in synthetic queries, no external requests. --hybrid explicitly
opts into the operator-configured embedding endpoint and data transmission.
No-RAG is an empty-context control, NOT a model answering without retrieval.
"""
import argparse
import hashlib
import json
import os
import tempfile
from collections import Counter
from pathlib import Path
from unittest.mock import patch

from agent.rag.store import ingest, search


def load_cases(paths):
    cases = []
    for path in paths:
        for line_number, line in enumerate(Path(path).read_text(encoding='utf-8').splitlines(), 1):
            if not line.strip():
                continue
            case = json.loads(line)
            for key in ('query', 'platform', 'expected_knowledge_id'):
                if key not in case:
                    raise ValueError(f'{path}:{line_number}: missing {key}')
            cases.append(dict(case, evaluation_id=f'{path}:{line_number}'))
    return cases


def summarize(rows):
    positives = [r for r in rows if r['expected_knowledge_id'] is not None]
    negatives = [r for r in rows if r['expected_knowledge_id'] is None]
    sections = [r for r in positives if r['expected_section'] is not None]
    mean = lambda values: sum(values) / len(values) if values else None
    return {
        'query_count': len(rows), 'positive_count': len(positives),
        'negative_count': len(negatives), 'section_case_count': len(sections),
        'hit_at_1': mean([r['rank'] == 1 for r in positives]),
        'hit_at_5': mean([r['rank'] is not None for r in positives]),
        'mrr_at_5': mean([1 / r['rank'] if r['rank'] else 0 for r in positives]),
        'negative_rejection_rate': mean([not r['hits'] for r in negatives]),
        'section_top1': mean([r['section_top1'] for r in sections]),
        'actual_mode_counts': dict(Counter(r['mode'] for r in rows)),
        'warning_count': sum(bool(r['warning']) for r in rows),
    }


def evaluate_arm(cases, arm, corpus, embedder=None):
    rows = []
    with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'FK_DATA_DIR': directory}):
        index = ingest(corpus, embedder) if arm != 'no_rag' else None
        for case in cases:
            result = ({'hits': [], 'mode': 'no_rag_empty_context', 'warning': ''}
                      if arm == 'no_rag' else search(
                          case['query'], platform=case['platform'], top_k=5,
                          sdk_version=case.get('sdk_version', ''),
                          as_of=case.get('as_of', ''),
                          exclude_case_id=case.get('case_id', ''),
                          public_only=True, embedder=embedder))
            hits = [{'knowledge_id': h['knowledge_id'], 'section': h['section'],
                     'chunk_id': h['chunk_id']} for h in result['hits']]
            expected = case['expected_knowledge_id']
            rank = next((i + 1 for i, h in enumerate(hits)
                         if h['knowledge_id'] == expected), None) if expected is not None else None
            section = case.get('expected_section')
            rows.append({
                'evaluation_id': case['evaluation_id'], 'query': case['query'],
                'expected_knowledge_id': expected, 'expected_section': section,
                'rank': rank, 'section_top1': bool(hits and rank == 1 and hits[0]['section'] == section)
                if section is not None else None,
                'hits': hits, 'mode': result['mode'], 'warning': result['warning'],
            })
    summary = summarize(rows)
    # An eligible query that silently fell back must not count as a hybrid run.
    fallback = arm == 'hybrid' and any(
        r['warning'] and not (
            not r['hits'] and r['warning'] ==
            'embedding model/index mismatch or empty corpus; lexical retrieval only'
        ) for r in rows)
    # This arm freshly ingests with this same provider identity, so the exact
    # mismatch-or-empty warning on empty results means no eligible corpus.
    # Those platform/PIT negatives do not require a query embedding request.
    return {'status': 'partial_with_fallback' if fallback else 'completed',
            'index': index, 'metrics': summary, 'rows': rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus', default='knowledge')
    parser.add_argument('--cases', nargs='+', default=['eval/rag/cases.jsonl', 'eval/rag/hard_cases.jsonl'])
    parser.add_argument('--hybrid', action='store_true', help='explicitly permit configured embedding calls')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    cases = load_cases(args.cases)
    provider = None
    if args.hybrid:
        from agent.rag.embeddings import configured_embedder
        provider = configured_embedder()
        if provider is None:
            parser.error('--hybrid requires explicitly configured real embeddings')
    arms = {name: evaluate_arm(cases, name, args.corpus) for name in ('no_rag', 'bm25')}
    arms['hybrid'] = (evaluate_arm(cases, 'hybrid', args.corpus, provider) if provider else {
        'status': 'not_run', 'reason': 'No real embedding execution requested; no synthetic vectors substituted.',
        'metrics': None})
    inputs = args.cases + sorted(str(p) for p in Path(args.corpus).rglob('*.json'))
    report = {
        'schema_version': 1,
        'scope': 'retrieval-only; no-RAG is empty-context control; BM25 includes production deterministic reranker',
        'data_provenance': 'Checked-in defaults are synthetic queries against public SDK source-reference documents. Custom inputs require independent provenance review.',
        'input_sha256': {p: hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in inputs},
        'generator_calls': 0, 'false_positive_rate': None, 'false_negative_rate': None,
        'answer_injection_success_rate': None,
        'unmeasured_reason': 'No reviewed incident labels or actual generated answers evaluated.',
        'arms': arms,
    }
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: {a: b for a, b in v.items() if a != 'rows'} for k, v in arms.items()}, ensure_ascii=False, indent=2))
    return 1 if arms['hybrid']['status'] == 'partial_with_fallback' else 0


if __name__ == '__main__':
    raise SystemExit(main())
