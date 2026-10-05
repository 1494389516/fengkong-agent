"""Operator-supplied conservative price ceiling; never an invented live quote."""
import json
import os
from pathlib import Path


def validate(value):
    if not isinstance(value,dict) or set(value)!={'version','rates_nano_usd_per_token','max_cost_nano_usd'}:
        raise ValueError('complete investigation pricing contract required')
    if not isinstance(value['version'],str) or not value['version'].strip():raise ValueError('pricing version required')
    rates=value['rates_nano_usd_per_token']
    if not isinstance(rates,dict) or set(rates)!={'generator','verifier','embedding'}:raise ValueError('price every provider component')
    if any(type(rate) is not int or rate<=0 for rate in rates.values()):raise ValueError('positive integer token prices required')
    cap=value['max_cost_nano_usd']
    if type(cap) is not int or not 0<cap<2**63:raise ValueError('positive bounded cost ceiling required')
    return json.loads(json.dumps(value))


def configured():
    path=os.environ.get('FK_INVESTIGATION_PRICING')
    if not path:return None
    return validate(json.loads(Path(path).read_text()))
