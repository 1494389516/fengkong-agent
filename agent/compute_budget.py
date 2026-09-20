"""Cooperative, bounded built-in feature execution; never truncate silently.

This bounds feature work, not arbitrary Python, RPCs, all service memory, or
SQLite write-lock waiting. The semaphore is per process, not a fleet quota.
"""
import contextvars
import json
import sqlite3
import threading
import time
from contextlib import contextmanager

from .compute_admission import DEFAULT_CONTRACT, validate_contract

_current = contextvars.ContextVar('feature_compute_budget', default=None)
_slots = threading.BoundedSemaphore(16)
_simulation = contextvars.ContextVar('simulation_compute_contract', default=None)


class ComputeBudgetExceeded(RuntimeError):
    pass


class Budget:
    def __init__(self, contract):
        self.contract = validate_contract(contract)
        self.deadline = time.monotonic() + contract['deadline_ms'] / 1000
        self.calls = 0

    def check(self):
        if time.monotonic() >= self.deadline:
            raise ComputeBudgetExceeded('feature_deadline')

    def account(self, rows):
        self.check()
        self.calls += 1
        if self.calls > self.contract['max_feature_calls']:
            raise ComputeBudgetExceeded('feature_call_limit')
        if len(rows) > self.contract['max_account_events']:
            raise ComputeBudgetExceeded('account_event_limit')


def current_budget():
    return _current.get()


@contextmanager
def feature_budget(contract=None):
    if _current.get() is not None:
        active = _current.get()
        if contract is not None:
            limits = validate_contract(contract)
            for key, value in limits.items():
                if type(value) is int and key != 'version':
                    active.contract[key] = min(active.contract[key], value)
            active.deadline = min(active.deadline, time.monotonic() + limits['deadline_ms'] / 1000)
        active.check()
        yield active
        return
    if contract is None:
        from .runtime_bundle import current_bundle
        bundle = current_bundle()
        contract = bundle['feature']['compute_contract'] if bundle else (_simulation.get() or DEFAULT_CONTRACT)
    budget = Budget(contract)
    if not _slots.acquire(blocking=False):
        raise ComputeBudgetExceeded('feature_concurrency_limit')
    token = _current.set(budget)
    try:
        yield budget
        budget.check()
    finally:
        _current.reset(token)
        _slots.release()


def bounded_history(rows, *, encoded=False):
    budget = current_budget()
    if budget is None:
        return [json.loads(r) for r in rows] if encoded else list(rows)
    limits = budget.contract
    result, total = [], 0
    for row in rows:
        budget.check()
        if len(result) >= limits['max_history_events']:
            raise ComputeBudgetExceeded('history_event_limit')
        if encoded and row is None:
            raise ComputeBudgetExceeded('event_byte_limit')
        raw = row if encoded else json.dumps(row, ensure_ascii=False, allow_nan=False)
        # Cheap length test before allocating UTF-8 bytes for an oversized value.
        if len(raw) > limits['max_event_bytes']:
            raise ComputeBudgetExceeded('event_byte_limit')
        size = len(raw.encode('utf-8'))
        total += size
        if size > limits['max_event_bytes'] or total > limits['max_history_bytes']:
            raise ComputeBudgetExceeded('history_byte_limit')
        result.append(json.loads(raw) if encoded else row)
    budget.check()
    return result


@contextmanager
def sql_budget(db):
    budget = current_budget()
    if budget is None:
        yield
        return
    steps = 0
    def progress():
        nonlocal steps
        steps += 100
        return int(steps >= budget.contract['max_sql_steps'] or time.monotonic() >= budget.deadline)
    db.set_progress_handler(progress, 100)
    try:
        yield
        budget.check()
    except sqlite3.OperationalError as exc:
        if 'interrupted' in str(exc).lower():
            raise ComputeBudgetExceeded('history_sql_budget') from exc
        raise
    finally:
        db.set_progress_handler(None, 0)


def fallback_result(event, error):
    from .runtime_bundle import annotate_bundle, current_bundle
    bundle = current_bundle()
    return annotate_bundle({
        'ts': time.time(), 'uid': event.get('uid'), 'action': 'review', 'hits': [], 'rules': [],
        'policy_version': bundle.get('versions', {}).get('policy') if bundle else None,
        'source': 'compute_budget_fallback', 'degraded': True,
        'degraded_reason': str(error), 'reason_codes': ['FEATURE_COMPUTE_BUDGET_EXCEEDED'],
        'escalate_to_human': True, 'agent_cannot_override': True,
        'features_snapshot': None,
        'components': {'features': {'status': 'unavailable', 'reason': str(error), 'required': True}},
    })


@contextmanager
def simulation_contract(contract):
    token = _simulation.set(validate_contract(contract))
    try:
        yield
    finally:
        _simulation.reset(token)


def simulation_key():
    from .compute_admission import digest
    return digest(_simulation.get() or DEFAULT_CONTRACT)


def sql_body_expression():
    budget = current_budget()
    if budget is None:
        return 'body'
    # Avoid transferring an oversized SQLite value into Python before checking it.
    return 'CASE WHEN length(CAST(body AS BLOB)) <= %d THEN body ELSE NULL END' % budget.contract['max_event_bytes']
