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
from .tools.datasource import data_dir, file_lock

FEATURE_SET="graph_risk_v1"
SHADOW_FEATURE_SET="graph_risk_shadow_v1"
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
    tenant,app=observation["tenant_id"],observation["app_id"]
    device=(observation["device_id"],observation["entity_generation"])
    # Serialize graph writes and projections across local workers. Invalidate first:
    # a crash can leave a feature pending, but cannot expose an obsolete one as fresh.
    with file_lock(data_dir()/".graph_projection"):
        store=graph_store()
        affected=set(store.devices_for_uid(tenant,app,observation.get("uid")))
        affected.add(device)
        online_feature_store().invalidate_devices(tenant,app,affected)
        try:
            store.append(observation)
            store.mark_dirty(tenant,app,affected-{device})
            result=_recompute_device(tenant,app,*device)
            store.clear_dirty(tenant,app,*device)
            return result
        except BaseException:
            online_feature_store().invalidate_devices(tenant,app,affected)
            raise


def recompute_device(tenant,app,device_id,generation,*,as_of=None):
    with file_lock(data_dir()/".graph_projection"):
        return _recompute_device(tenant,app,device_id,generation,as_of=as_of)


def _recompute_device(tenant,app,device_id,generation,*,as_of=None):
    latest=graph_store().latest_recorded_at(tenant,app)
    anchor=max((latest if latest is not None else time.time()),
               (as_of if as_of is not None else float("-inf")))
    rows,truncated=graph_store().scope_rows(tenant,app,anchor,limit=MAX_ROWS)
    primary_name=os.environ.get("FK_GRAPH_ALGORITHM","community_v1")
    algorithm=graph_algorithm(primary_name)
    result=algorithm.compute(rows,device_id,generation,truncated=truncated,as_of=anchor)
    result.update(device_id=device_id,entity_generation=generation,as_of=anchor)
    store=online_feature_store()
    store.put(tenant,app,"device",device_id,generation,FEATURE_SET,
              result,computed_at=time.time())

    # Challenger is shadow-only: it cannot affect Decision. Persist its output and
    # divergence so offline evaluation can decide whether a release proposal is justified.
    shadow_name=os.environ.get("FK_GRAPH_SHADOW_ALGORITHM","").strip()
    if shadow_name and shadow_name!=primary_name:
        shadow=graph_algorithm(shadow_name).compute(
            rows,device_id,generation,truncated=truncated,as_of=anchor)
        shadow.update(device_id=device_id,entity_generation=generation,as_of=anchor,
                      shadow_of=primary_name,
                      score_delta=round(float(shadow.get("community_risk_density",0.0))-
                                        float(result.get("community_risk_density",0.0)),6))
        store.put(tenant,app,"device",device_id,generation,SHADOW_FEATURE_SET,
                  shadow,computed_at=time.time())
    return result


def refresh_dirty_devices(*,limit=100):
    if type(limit) is not int or not 1<=limit<=1000:
        raise ValueError("limit must be 1..1000")
    refreshed=0;failed=[]
    with file_lock(data_dir()/".graph_projection"):
        store=graph_store()
        for tenant,app,device,generation in store.dirty_devices(limit):
            try:
                _recompute_device(tenant,app,device,generation)
                store.clear_dirty(tenant,app,device,generation)
                refreshed+=1
            except Exception as exc:
                online_feature_store().invalidate_devices(
                    tenant,app,[(device,generation)])
                failed.append({"device_id":device,"error":type(exc).__name__,
                               "phase":"graph_refresh"})
    return {"refreshed":refreshed,"failed":failed}


def lookup(tenant,app,device_id,generation,*,connection=None,max_age=MAX_FEATURE_AGE_SECONDS):
    # connection is accepted for compatibility but deliberately ignored: graph
    # features live outside the online decision SQLite authority.
    result=online_feature_store().get(
        tenant,app,"device",device_id,generation,FEATURE_SET,max_age=max_age)
    # A bounded snapshot is partial evidence; do not present it as current.
    return None if result is not None and result.get("truncated") else result


def consume_pending(*,limit=100):
    from .event_bus import event_bus
    bus=event_bus();processed=0;failed=[]
    for event in bus.claim("risk.evidence.accepted",limit=limit,lease_seconds=30,max_attempts=5):
        try:
            ingest_observation(event.payload)
            if bus.acknowledge(event.event_id,event.lease_token):processed+=1
        except Exception as exc:
            bus.fail(event.event_id,event.lease_token,type(exc).__name__,max_attempts=5)
            failed.append({"event_id":event.event_id,"error":type(exc).__name__,
                           "attempts":event.attempts})
    refresh=refresh_dirty_devices(limit=limit)
    failed.extend(refresh["failed"])
    return {"processed":processed,"refreshed":refresh["refreshed"],"failed":failed}
