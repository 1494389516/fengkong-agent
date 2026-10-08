"""Graph worker heartbeat and backlog health.

This is operational state only; it never changes a risk decision.
"""
import json
import math
import time

from .tools.datasource import data_dir,atomic_write_json

TOPIC="risk.evidence.accepted"


def _path():
    return data_dir()/"out"/"graph_worker_health.json"


def _number(value):
    if type(value) not in (int,float) or value<0 or not math.isfinite(value):
        raise ValueError('nonnegative finite number required')
    return value


def _count(value):
    if type(value) is not int or value<0:
        raise ValueError('nonnegative integer required')
    return value


def _validate(payload):
    """Validate before defaults, coercions or comparisons can hide missing data."""
    if not isinstance(payload,dict) or payload['topic']!=TOPIC:
        raise ValueError('invalid heartbeat')
    _number(payload['updated_at'])
    for key in ('processed','failed'):
        _count(payload[key])
    bus=payload['bus'];projection=payload['projection']
    if not isinstance(bus,dict) or not isinstance(projection,dict):
        raise ValueError('invalid telemetry objects')
    for key in ('pending','ready','leased','dead_letters','max_attempts'):
        _count(bus[key])
    _number(bus['oldest_pending_age_seconds'])
    if bus['pending']!=bus['ready']+bus['leased']:
        raise ValueError('inconsistent bus counts')
    for key in ('pending','total','available','unavailable'):
        _count(projection[key])
    _number(projection['oldest_pending_age_seconds'])
    ratio=_number(projection['availability'])
    if projection['total']!=projection['available']+projection['unavailable']:
        raise ValueError('inconsistent projection counts')
    expected=projection['available']/projection['total'] if projection['total'] else 1.0
    if ratio>1 or not math.isclose(ratio,expected,rel_tol=1e-9,abs_tol=1e-12):
        raise ValueError('inconsistent availability')


def write_heartbeat(consume_result,bus_stats,*,now=None):
    stamp=_number(time.time() if now is None else now)
    from .graph_store import graph_store
    from .online_feature_store import online_feature_store
    projection={**graph_store().dirty_stats(now=stamp),
                **online_feature_store().availability_stats(now=stamp)}
    payload={
        "updated_at":stamp,
        "topic":TOPIC,
        "processed":_count(consume_result["processed"]),
        "failed":len(consume_result.get("failed") or []),
        "bus":dict(bus_stats),
        "projection":projection,
    }
    _validate(payload)
    atomic_write_json(_path(),payload)
    return payload


def read_health(*,max_age_seconds=10.0,max_backlog_age_seconds=60.0,now=None):
    p=_path()
    def degraded(reason):
        return {"level":"degraded","reason":reason,"path":str(p)}
    try:
        anchor=_number(time.time() if now is None else now)
        _number(max_age_seconds);_number(max_backlog_age_seconds)
    except (ValueError,TypeError,OverflowError):
        return degraded('health_config_invalid')
    try:
        with p.open('rb') as handle:
            raw=handle.read(65537)
        if len(raw)>65536:
            raise ValueError('heartbeat exceeds size budget')
        payload=json.loads(raw)
        _validate(payload)
        updated=payload['updated_at']
        bus=payload['bus']
    except FileNotFoundError:
        return degraded('heartbeat_missing')
    except (OSError,ValueError,TypeError,KeyError,OverflowError,RecursionError):
        return degraded('heartbeat_invalid')
    if updated>anchor:
        return degraded('heartbeat_future')
    age=anchor-updated
    backlog_age=bus['oldest_pending_age_seconds']
    dead=bus['dead_letters']
    level="ok"
    reasons=[]
    if not math.isfinite(age) or age>max_age_seconds:
        level="degraded";reasons.append("heartbeat_stale")
    if backlog_age>max_backlog_age_seconds:
        level="degraded";reasons.append("backlog_old")
    if dead>0:
        level="degraded";reasons.append("dead_letters_present")
    projection=payload['projection']
    if projection['pending']>0:
        level="degraded";reasons.append("projection_refresh_pending")
    if projection['unavailable']>0:
        level="degraded";reasons.append("projection_unavailable")
    if payload['failed']>0:
        level="degraded";reasons.append("worker_failures")
    return {
        "level":level,
        "reason":",".join(reasons) if reasons else "healthy",
        "heartbeat_age_seconds":round(age,3),
        "bus":bus,
        "projection":projection,
        "processed":payload["processed"],
        "failed":payload["failed"],
        "path":str(p),
    }
