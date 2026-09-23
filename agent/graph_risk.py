"""Asynchronous server-side graph feature pipeline.

Accepted Collector evidence is persisted in a dedicated GraphStore, processed by
a versioned algorithm, then materialized into the OnlineFeatureStore. Decision
reads only the feature projection; it never queries the graph synchronously.
"""
import math
import os
import time

from .graph_algorithms import graph_algorithm, MAX_ROWS
from .graph_store import graph_store
from .online_feature_store import online_feature_store

FEATURE_SET="graph_risk_v1"
MAX_FEATURE_AGE_SECONDS=300


def _finite(value):
    return type(value) in (int,float) and math.isfinite(value)


def ingest_observation(observation):
    required=("evidence_id","tenant_id","app_id","device_id","entity_generation")
    if not isinstance(observation,dict) or any(not observation.get(k) for k in required):
        raise ValueError("complete server-bound observation required")
    if observation.get("identity_trust")!="server_bound":
        raise ValueError("graph projection accepts server-bound identity only")
    if not _finite(observation.get("observed_at")) or not _finite(observation.get("recorded_at")):
        raise ValueError("finite graph timestamps required")
    store=graph_store()
    store.append(observation)
    return recompute_device(observation["tenant_id"],observation["app_id"],
                            observation["device_id"],observation["entity_generation"],
                            as_of=observation["recorded_at"])


def recompute_device(tenant,app,device_id,generation,*,as_of=None):
    anchor=time.time() if as_of is None else as_of
    rows,truncated=graph_store().scope_rows(tenant,app,anchor,limit=MAX_ROWS)
    algorithm=graph_algorithm(os.environ.get("FK_GRAPH_ALGORITHM","community_v1"))
    result=algorithm.compute(rows,device_id,generation,truncated=truncated)
    result.update(device_id=device_id,entity_generation=generation,as_of=anchor)
    online_feature_store().put(tenant,app,"device",device_id,generation,FEATURE_SET,
                               result,computed_at=anchor)
    return result


def lookup(tenant,app,device_id,generation,*,connection=None,max_age=MAX_FEATURE_AGE_SECONDS):
    # connection is accepted for compatibility but deliberately ignored: graph
    # features live outside the online decision SQLite authority.
    return online_feature_store().get(
        tenant,app,"device",device_id,generation,FEATURE_SET,max_age=max_age)


def consume_pending(*,limit=100):
    from .event_bus import event_bus
    bus=event_bus();processed=0;failed=[]
    for event in bus.pending(limit=limit):
        if event.topic!="risk.evidence.accepted":
            continue
        try:
            ingest_observation(event.payload)
            if bus.acknowledge(event.event_id):processed+=1
        except Exception as exc:
            failed.append({"event_id":event.event_id,"error":type(exc).__name__})
    return {"processed":processed,"failed":failed}
