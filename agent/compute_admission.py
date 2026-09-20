"""Trusted admission for the built-in account-history feature executor.

No Agent-supplied code, cost estimates or graph plans are executable here.
Work units are a conservative sizing proxy, NOT a wall-clock proof. Release
operators must supply measured evidence for their deployment capacity envelope.
"""
import copy
import hashlib
import json
import math
from pathlib import Path


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    allow_nan=False).encode()).hexdigest()


DEFAULT_CONTRACT = {
    'version': 1, 'operator': 'account_history_v1', 'fallback': 'review',
    'max_history_events': 10000, 'max_account_events': 1000,
    'max_history_bytes': 8 * 1024 * 1024, 'max_event_bytes': 16384,
    'max_feature_calls': 2, 'deadline_ms': 50, 'max_sql_steps': 200000,
}
SCENARIOS = frozenset(('cold_cache', 'hot_key', 'max_input', 'full_trigger',
                       'overload', 'dependency_failure'))


def implementation_digest():
    root = Path(__file__).resolve().parent
    paths = ('compute_admission.py', 'compute_budget.py', 'engine.py',
             'tools/featurelib.py', 'tools/datasource.py', 'tools/online_store.py',
             'tools/rules.py')
    return digest({p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in paths})


def validate_contract(contract):
    if not isinstance(contract, dict) or set(contract) != set(DEFAULT_CONTRACT):
        raise ValueError('complete compute_contract required; unknown fields are forbidden')
    for key, maximum in DEFAULT_CONTRACT.items():
        value = contract[key]
        if key in ('operator', 'fallback', 'version'):
            if type(value) is not type(maximum) or value != maximum:
                raise ValueError('unsupported compute contract: ' + key)
        elif type(value) is not int or not 1 <= value <= maximum:
            raise ValueError('compute limit outside platform boundary: ' + key)
    if contract['max_account_events'] > contract['max_history_events']:
        raise ValueError('account limit exceeds history limit')
    if contract['max_event_bytes'] > contract['max_history_bytes']:
        raise ValueError('event byte limit exceeds history byte limit')
    return copy.deepcopy(contract)


def validate_dependencies(dependencies):
    from .tools.featurelib import FEATURE_CATALOG
    supported = {f['key'] for f in FEATURE_CATALOG if f['source'] == 'account_features'}
    if not isinstance(dependencies, list) or any(not isinstance(f, str) or f not in supported for f in dependencies):
        raise ValueError('unbounded or unsupported feature dependency; implement and register a bounded executor first')


def admit_bundle(bundle):
    feature = bundle.get('feature')
    if not isinstance(feature, dict):
        raise ValueError('feature mapping with compute_contract required')
    # Reject inert declarations: adding a field must never pretend to add a feature.
    if set(feature) != {'catalog_version', 'compute_contract'}:
        raise ValueError('unsupported feature plan; only catalog_version and compute_contract accepted')
    from .tools.featurelib import FEATURE_CATALOG_VERSION
    if feature['catalog_version'] != FEATURE_CATALOG_VERSION:
        raise ValueError('unsupported feature catalog')
    contract = validate_contract(feature['compute_contract'])
    strategy = bundle.get('strategy')
    if not isinstance(strategy, dict):
        raise ValueError('strategy mapping required for compute admission')
    validate_dependencies(strategy.get('feature_dependencies', []))
    n, k = contract['max_history_events'], contract['max_account_events']
    # Index/filter passes plus bounded account scans and two sorts per call.
    work = 4 * n * contract['max_feature_calls'] + contract['max_feature_calls'] * (20 * k + 2 * k * max(1, k.bit_length()))
    return {'version': 1, 'bundle_digest': digest(bundle),
            'implementation_digest': implementation_digest(),
            'contract': contract, 'work_units_upper': work,
            'cost_model': 'bounded_input_proxy_not_latency_proof'}


def validate_capacity(capacity):
    keys = {'target_qps', 'cpu_cores', 'max_utilization', 'max_rss_bytes', 'max_p99_ms'}
    if not isinstance(capacity, dict) or set(capacity) != keys:
        raise ValueError('operator-owned compute capacity envelope required')
    for k, v in capacity.items():
        if type(v) not in (int, float) or not math.isfinite(v) or v <= 0:
            raise ValueError('invalid compute capacity: ' + k)
    if capacity['max_utilization'] > 1:
        raise ValueError('max_utilization must not exceed one')
    return copy.deepcopy(capacity)


def verify_performance(proof, admission, capacity):
    """Evidence is accepted only from the controller's authenticated stage role.

    Digest binding is not proof that a benchmark actually ran. Production must
    provision benchmark-runner credentials independently of Agent credentials.
    """
    capacity = validate_capacity(capacity)
    evidence = proof.get('evidence', {})
    if not isinstance(evidence, dict) or proof.get('evidence_digest') != digest(evidence):
        raise ValueError('performance evidence digest required')
    report = evidence.get('compute_performance') if isinstance(evidence, dict) else None
    if not isinstance(report, dict) or report.get('admission_digest') != digest(admission):
        raise ValueError('performance evidence must bind computed admission digest')
    if report.get('capacity_digest') != digest(capacity):
        raise ValueError('performance evidence capacity mismatch')
    scenarios = report.get('scenarios')
    if not isinstance(scenarios, dict) or set(scenarios) != SCENARIOS:
        raise ValueError('complete adversarial performance scenarios required')
    for name, row in scenarios.items():
        if not isinstance(row, dict) or type(row.get('sample_count')) is not int or row['sample_count'] < 1000:
            raise ValueError('at least 1000 measured requests per scenario required')
        for field in ('offered_qps', 'completed_qps', 'cpu_ms_per_request', 'p99_ms',
                      'peak_rss_bytes', 'timeout_rate', 'degraded_rate'):
            value = row.get(field)
            if type(value) not in (float, int) or not math.isfinite(value) or value < 0:
                raise ValueError('invalid performance metric: ' + field)
        if row['offered_qps'] < capacity['target_qps'] or row['completed_qps'] < capacity['target_qps']:
            raise ValueError('benchmark did not sustain target arrival and completion rate')
        if name == 'overload' and row['offered_qps'] < 2 * capacity['target_qps']:
            raise ValueError('overload scenario requires at least twice target arrival rate')
        if row['timeout_rate'] != 0 or not 0 <= row['degraded_rate'] <= 1:
            raise ValueError('timeouts or invalid degradation measurements')
        if name not in ('overload', 'dependency_failure') and row['degraded_rate'] != 0:
            raise ValueError('nominal capacity cannot be demonstrated by fallback responses')
        if row.get('bounded_resources') is not True or row.get('fallback_verified') is not True:
            raise ValueError('resource bounds and fallback must be exercised')
        if row['p99_ms'] > min(capacity['max_p99_ms'], admission['contract']['deadline_ms']):
            raise ValueError('feature latency budget exceeded')
        if row['cpu_ms_per_request'] * capacity['target_qps'] / 1000 > capacity['cpu_cores'] * capacity['max_utilization']:
            raise ValueError('aggregate CPU budget exceeded')
        if row['peak_rss_bytes'] > capacity['max_rss_bytes']:
            raise ValueError('memory budget exceeded')


def verify_record(record, capacity=None, *, require_current_implementation=True):
    computed = admit_bundle(record['bundle'])
    if not require_current_implementation:
        previous = record.get('compute_admission', {}).get('implementation_digest')
        if not isinstance(previous, str) or len(previous) != 64 or any(c not in '0123456789abcdef' for c in previous):
            raise ValueError('invalid historical implementation digest')
        computed['implementation_digest'] = previous
    if record.get('compute_admission') != computed:
        raise ValueError('compute admission changed; resubmit and benchmark again')
    if capacity is not None and record.get('compute_capacity') != capacity:
        raise ValueError('deployment compute capacity changed; resubmit')
    return computed
