"""Durable work accounting at the actual data/tool boundaries.

Counts are logical rows and canonical JSON bytes, not SQLite physical pages or
wire/TLS bytes. Each retry consumes work again; committed step replay does not
re-enter these boundaries. Existing per-operation bounds remain in force.
"""
import json
import uuid


class ResourceBudgetExceeded(PermissionError):
    pass


def json_bytes(value):
    return len(json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode())


def consume(**amounts):
    from .run_ledger import _current
    ledger=_current.get()
    if ledger is None:return
    selected={k:v for k,v in amounts.items() if v and 'max_'+k in ledger.budget_contract}
    if not selected:return
    receipt='work:'+uuid.uuid4().hex
    try:
        with ledger.transaction():
            for resource,amount in selected.items():ledger._charge_resource(receipt,resource,amount)
    except PermissionError as exc:
        # Do not turn exhaustion into a normal tool result or a benign verdict.
        raise ResourceBudgetExceeded(str(exc)) from exc


def read_rows(rows):
    consume(scanned_rows=len(rows),input_bytes=sum(json_bytes(row) for row in rows))


def read_value(value):
    consume(input_bytes=json_bytes(value))
