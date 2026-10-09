"""Asynchronous server-side graph feature pipeline.

Accepted Collector evidence is persisted in a dedicated GraphStore, processed by
a versioned algorithm, then materialized into the OnlineFeatureStore. Decision
reads only the feature projection; it never queries the graph synchronously.
"""
import math
import os
import time

from .graph_algorithms import graph_algorithm, MAX_ROWS, MAX_NODES
from .graph_store import graph_store
from .online_feature_store import online_feature_store
from .tools.datasource import data_dir, file_lock
from .storage import projection_lock

FEATURE_SET="graph_risk_v1"
SHADOW_FEATURE_SET="graph_risk_shadow_v1"
MAX_FEATURE_AGE_SECONDS=300


def _finite(value):
    return type(value) in (int,float) and math.isfinite(value)


def _affected_devices(store, observation):
    """Bounded dependency closure; None means snapshot-wide invalidation required."""
    # Temporal weights depend on the scope clock even in disconnected components.
    if os.environ.get('FK_GRAPH_ALGORITHM','community_v1') != 'community_v1' or os.environ.get('FK_GRAPH_SHADOW_ALGORITHM','').strip() not in ('','community_v1'):
        return None
    tenant,app=observation['tenant_id'],observation['app_id']
    anchor=max(store.latest_recorded_at(tenant,app) or observation['recorded_at'],observation['recorded_at'])
    rows,truncated=store.scope_rows(tenant,app,anchor,limit=MAX_ROWS)
    if truncated or len(rows)>=MAX_ROWS:
        return None  # Insertion/eviction can alter other components of the bounded view.
    edges={}
    def add(device,generation,uid):
        d=('device',device,generation)
        edges.setdefault(d,set())
        if uid:
            u=('uid',uid)
            edges.setdefault(u,set()).add(d);edges[d].add(u)
    for _,uid,device,generation,_,_,_ in rows:
        add(device,generation,uid)
    add(observation['device_id'],observation['entity_generation'],observation.get('uid'))
    if len(edges)>=MAX_NODES:
        return None  # Node-budget eviction is also scope-wide.
    target=('device',observation['device_id'],observation['entity_generation'])
    seen={target};pending=[target]
    while pending:
        node=pending.pop()
        for neighbor in edges[node]-seen:
            seen.add(neighbor);pending.append(neighbor)
    return {(n[1],n[2]) for n in seen if n[0]=='device'}


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
    with projection_lock():
        store=graph_store()
        affected=_affected_devices(store,observation)
        # Queue work before invalidation; retries preserve the original queue age.
        def invalidate():
            if affected is None:
                online_feature_store().invalidate_scope(tenant,app)
            else:
                online_feature_store().invalidate_devices(tenant,app,affected)
        if affected is None:
            store.mark_scope_dirty(tenant,app)
        else:
            store.mark_dirty(tenant,app,affected)
        invalidate()
        try:
            store.append(observation)
            store.mark_dirty(tenant,app,{device})
            result=_recompute_device(tenant,app,*device)
            store.clear_dirty(tenant,app,*device)
            return result
        except BaseException:
            invalidate()
            raise


def recompute_device(tenant,app,device_id,generation,*,as_of=None):
    with projection_lock():
        return _recompute_device(tenant,app,device_id,generation,as_of=as_of)


def _recompute_device(tenant,app,device_id,generation,*,as_of=None,_snapshot=None,_computed=None):
    if _snapshot is None:
        latest=graph_store().latest_recorded_at(tenant,app)
        anchor=max((latest if latest is not None else time.time()),
                   (as_of if as_of is not None else float("-inf")))
        rows,truncated=graph_store().scope_rows(tenant,app,anchor,limit=MAX_ROWS)
    else:
        anchor,rows,truncated=_snapshot
    primary_name=os.environ.get("FK_GRAPH_ALGORITHM","community_v1")
    algorithm=graph_algorithm(primary_name)
    result=dict(_computed) if _computed is not None else algorithm.compute(rows,device_id,generation,truncated=truncated,as_of=anchor)
    result.update(device_id=device_id,entity_generation=generation,as_of=anchor)
    store=online_feature_store()
    values={FEATURE_SET:result}

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
        values[SHADOW_FEATURE_SET]=shadow
    # Primary and shadow become visible together, only after both computations
    # succeed. Failure retains the previous complete publication and its age.
    store.put_many(tenant,app,"device",device_id,generation,values,computed_at=time.time())
    return result


def refresh_dirty_devices(*,limit=100):
    if type(limit) is not int or not 1<=limit<=1000:
        raise ValueError("limit must be 1..1000")
    refreshed=0;failed=[]
    with projection_lock():
        store=graph_store()
        groups={}
        for tenant,app,device,generation in store.dirty_devices(limit):
            groups.setdefault((tenant,app),[]).append((device,generation))
        for (tenant,app),targets in groups.items():
            try:
                latest=store.latest_recorded_at(tenant,app)
                anchor=latest if latest is not None else time.time()
                rows,truncated=store.scope_rows(tenant,app,anchor,limit=MAX_ROWS)
                algorithm=graph_algorithm(os.environ.get("FK_GRAPH_ALGORITHM","community_v1"))
                results=algorithm.compute_many(rows,targets,truncated=truncated,as_of=anchor)
            except Exception as exc:
                online_feature_store().invalidate_devices(tenant,app,targets)
                store.defer_dirty(tenant,app,targets)
                failed.extend({'device_id':device,'error':type(exc).__name__,'phase':'graph_refresh'} for device,_ in targets)
                continue
            for device,generation in targets:
                try:
                    _recompute_device(tenant,app,device,generation,_snapshot=(anchor,rows,truncated),
                                      _computed=results[(device,generation)])
                    store.clear_dirty(tenant,app,device,generation)
                    refreshed+=1
                except Exception as exc:
                    online_feature_store().invalidate_devices(tenant,app,[(device,generation)])
                    store.defer_dirty(tenant,app,[(device,generation)])
                    failed.append({'device_id':device,'error':type(exc).__name__,'phase':'graph_refresh'})
    return {"refreshed":refreshed,"failed":failed}


def lookup(tenant,app,device_id,generation,*,connection=None,max_age=MAX_FEATURE_AGE_SECONDS):
    # connection is accepted for compatibility but deliberately ignored: graph
    # features live outside the online decision SQLite authority.
    policy=os.environ.get('FK_GRAPH_REFRESH_POLICY','strict')
    if policy not in ('strict','bounded_previous'):
        raise ValueError('invalid graph refresh policy')
    result=online_feature_store().get(
        tenant,app,"device",device_id,generation,FEATURE_SET,max_age=max_age,
        allow_previous=policy=='bounded_previous')
    if result and result.get('algorithm') != os.environ.get('FK_GRAPH_ALGORITHM','community_v1'):
        return None
    # A bounded snapshot is partial evidence; do not present it as current.
    return None if result is not None and result.get("truncated") else result


def consume_pending(*,limit=100):
    from .event_bus import event_bus
    from .lease_guard import keep_lease, LeaseLost
    bus=event_bus();processed=0;failed=[]
    bus._validate_limit(limit)
    for _ in range(limit):
        # Claim just in time: waiting behind other events must not spend a lease.
        batch=bus.claim("risk.evidence.accepted",limit=1,lease_seconds=30,max_attempts=5)
        if not batch: break
        event=batch[0]
        try:
            with keep_lease(bus,event):
                ingest_observation(event.payload)
            if not bus.acknowledge(event.event_id,event.lease_token):
                raise LeaseLost("acknowledgement rejected")
            processed+=1
        except Exception as exc:
            bus.fail(event.event_id,event.lease_token,type(exc).__name__,max_attempts=5)
            failed.append({"event_id":event.event_id,"error":type(exc).__name__,
                           "attempts":event.attempts})
            # Do not burn all retries of the same failing event in one drain.
            break
    refresh=refresh_dirty_devices(limit=limit)
    failed.extend(refresh["failed"])
    return {"processed":processed,"refreshed":refresh["refreshed"],"failed":failed}
