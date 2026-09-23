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


def write_heartbeat(consume_result,bus_stats,*,now=None):
    stamp=time.time() if now is None else float(now)
    payload={
        "updated_at":stamp,
        "topic":TOPIC,
        "processed":int(consume_result.get("processed",0)),
        "failed":len(consume_result.get("failed") or []),
        "bus":dict(bus_stats),
    }
    atomic_write_json(_path(),payload)
    return payload


def read_health(*,max_age_seconds=10.0,max_backlog_age_seconds=60.0,now=None):
    anchor=time.time() if now is None else float(now)
    p=_path()
    if not p.exists():
        return {"level":"degraded","reason":"heartbeat_missing","path":str(p)}
    try:
        payload=json.loads(p.read_text(encoding="utf-8"))
        updated=float(payload["updated_at"])
        bus=payload.get("bus") or {}
    except Exception:
        return {"level":"degraded","reason":"heartbeat_invalid","path":str(p)}
    age=max(0.0,anchor-updated)
    backlog_age=float(bus.get("oldest_pending_age_seconds") or 0.0)
    dead=int(bus.get("dead_letters") or 0)
    level="ok"
    reasons=[]
    if not math.isfinite(age) or age>max_age_seconds:
        level="degraded";reasons.append("heartbeat_stale")
    if backlog_age>max_backlog_age_seconds:
        level="degraded";reasons.append("backlog_old")
    if dead>0:
        level="degraded";reasons.append("dead_letters_present")
    return {
        "level":level,
        "reason":",".join(reasons) if reasons else "healthy",
        "heartbeat_age_seconds":round(age,3),
        "bus":bus,
        "processed":payload.get("processed",0),
        "failed":payload.get("failed",0),
        "path":str(p),
    }
