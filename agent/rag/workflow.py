"""Server-enforced state for bounded corrective retrieval investigations."""
import re


PURPOSES = frozenset(('interpretation', 'support', 'counterevidence'))
ATTEMPT_REASONS = frozenset(('initial', 'no_match', 'low_relevance',
                             'missing_counterevidence', 'broaden_terms'))
MAX_KNOWLEDGE_SEARCHES = 3


def _search_limit(snapshot):
    value = snapshot.get('budget', {}).get('max_knowledge_searches', MAX_KNOWLEDGE_SEARCHES)
    if type(value) is not int or not 1 <= value <= 5:
        raise ValueError('max_knowledge_searches must be 1..5')
    return value


def begin_search(state, arguments):
    """Reserve an attempt before retrieval; duplicate and excess attempts fail closed."""
    if not state.get('event_evidence_loaded'):
        raise PermissionError('read event evidence before knowledge retrieval')
    purpose = arguments.setdefault('purpose', 'interpretation')
    reason = arguments.setdefault('attempt_reason', 'initial')
    if purpose not in PURPOSES:
        raise ValueError('invalid knowledge search purpose')
    if reason not in ATTEMPT_REASONS:
        raise ValueError('invalid knowledge search attempt reason')
    query = arguments.get('query')
    normalized = re.sub(r'\s+', ' ', query.strip()).casefold() if isinstance(query, str) else ''
    signature = (normalized, arguments.get('platform', ''),
                 tuple(sorted(arguments.get('detector_ids') or [])),
                 arguments.get('sdk_version', ''))
    history = state.setdefault('retrieval_trace', [])
    used = sum(row.get('status') != 'rejected_duplicate' for row in history)
    if any(row.get('signature') == signature for row in history):
        history.append({'attempt': used + 1, 'purpose': purpose,
                        'attempt_reason': reason, 'status': 'rejected_duplicate',
                        'query_digest': _query_digest(normalized)})
        raise PermissionError('duplicate knowledge search; rewrite or stop')
    limit = _search_limit(state['snapshot'])
    if used >= limit:
        raise PermissionError('knowledge search budget exhausted')
    history.append({'attempt': used + 1, 'purpose': purpose,
                    'attempt_reason': reason, 'status': 'pending',
                    'query_digest': _query_digest(normalized), 'signature': signature})
    return history[-1]


def finish_search(state, result=None, error=''):
    history = state.setdefault('retrieval_trace', [])
    row = next((item for item in reversed(history) if item.get('status') == 'pending'), None)
    if row is None:
        return
    if error:
        row.update(status='error', error_type=error)
        return
    hits = result.get('hits', []) if isinstance(result, dict) else []
    row.update(status=result.get('status', 'error'), mode=result.get('mode', ''),
               hit_count=len(hits), hit_ids=[hit.get('chunk_id') for hit in hits[:10]],
               warning=bool(result.get('warning')))


def record_event_evidence(state, result):
    registry = {}
    event_id = result.get('event_id')
    if isinstance(event_id, str) and event_id:
        registry['event:' + event_id] = {'kind': 'event_fact'}
    decision_id = result.get('decision_id')
    if isinstance(decision_id, str) and decision_id:
        registry['decision:' + decision_id] = {'kind': 'recorded_decision'}
    for observation in result.get('sdk_observations', []):
        if isinstance(observation, dict) and isinstance(observation.get('evidence_id'), str):
            registry['sdk:' + observation['evidence_id']] = {'kind': 'sdk_observation'}
    state['event_evidence_loaded'] = True
    state['event_evidence_registry'] = registry
    return [{'ref': ref, **metadata} for ref, metadata in registry.items()]


def retrieval_audit(state):
    rows = []
    for source in state.get('retrieval_trace', []):
        row = {key: value for key, value in source.items() if key != 'signature'}
        rows.append(row)
    completed = [row for row in rows if row['status'] not in ('pending', 'rejected_duplicate')]
    purposes = sorted({row['purpose'] for row in completed})
    matched = any(row.get('hit_count', 0) for row in completed)
    counter_rows = [row for row in completed if row['purpose'] == 'counterevidence']
    counter_matched = any(row.get('hit_count', 0) for row in counter_rows)
    if not rows:
        outcome = 'not_used'
    elif matched and 'counterevidence' in purposes:
        outcome = 'balanced'
    elif matched:
        outcome = 'counterevidence_not_checked'
    elif len(completed) >= _search_limit(state['snapshot']):
        outcome = 'exhausted_no_match'
    else:
        outcome = 'knowledge_gap'
    return {'outcome': outcome, 'attempts': rows, 'attempt_count': len(completed),
            'max_attempts': _search_limit(state['snapshot']), 'purposes': purposes,
            'counterevidence_search_performed': bool(counter_rows),
            'counterevidence_hit': counter_matched}


def _query_digest(value):
    import hashlib
    return hashlib.sha256(value.encode()).hexdigest()[:16]
