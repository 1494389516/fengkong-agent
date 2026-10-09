"""Bounded immutable investigation inputs, with explicit capture limitations."""
import hashlib
import json
import sqlite3
import time
from .tools.datasource import data_dir
from .storage import postgres, online_available, online_reader, json_text


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def build(snapshot):
    root = data_dir()
    anchor = snapshot['as_of']
    entity = snapshot['entity_ref']
    rows = []; nodes = set(); seen = set(); byte_count = 0; partial = False
    source = root / 'online.sqlite3'
    if online_available():
        db = online_reader()
        ticks = [0]
        def bounded_scan():
            ticks[0] += 1
            return ticks[0] > 2000
        if postgres(db):
            db.execute("SET statement_timeout = '2s'")
        else:
            db.set_progress_handler(bounded_scan, 1000)
        try:
            # Expand one shared-device neighborhood, never the tenant's full graph.
            queries = [('uid', entity)]
            devices = set()
            for field, value in queries:
                cursor = db.execute("SELECT body FROM events WHERE tenant=? AND app=? AND "
                    + json_text(db, 'body', field) + "=? AND occurred_at<? AND recorded_at<=? "
                    "AND occurred_at>=? ORDER BY occurred_at,event_id LIMIT 1001",
                    (snapshot['tenant_id'], snapshot['app_id'], value, anchor, anchor, anchor-30*86400))
                for (raw,) in cursor:
                    event = json.loads(raw)
                    key = digest(event)
                    if key in seen: continue
                    extra = {(k,str(event[k])) for k in ('uid','device_id','ip') if event.get(k)}
                    if len(rows)>=1000 or len(nodes|extra)>snapshot['budget']['max_graph_nodes'] or byte_count+len(raw.encode())>8*1024*1024:
                        partial=True; break
                    rows.append(event);seen.add(key);nodes |= extra;byte_count += len(raw.encode())
                    if field == 'uid' and event.get('device_id') and event['device_id'] not in devices:
                        devices.add(event['device_id']);queries.append(('device_id',event['device_id']))
                if partial: break
        except Exception as exc:
            if not ((isinstance(exc,sqlite3.OperationalError) and 'interrupted' in str(exc))
                    or (postgres(db) and getattr(exc,'sqlstate',None)=='57014')): raise
            partial=True
        finally:
            db.close()
    files = {}
    # Freeze auxiliary JSON views actually used by existing tools. Their historical
    # known-at provenance may be absent; capture time is NOT an event-time version.
    for name in ('accounts.json','blacklist.json','labels.json','device_intel.json','ip_intel.json',
                 'reports.json','appeals.json','thresholds.json','watchlist.json'):
        path=root/name
        if path.exists():
            with path.open('rb') as handle: raw=handle.read(8*1024*1024+1)
            if len(raw)>8*1024*1024: raise ValueError('snapshot dependency exceeds byte limit')
            files[name]=json.loads(raw)
        else:
            files[name]=None
    from .investigation_pricing import configured
    pricing=configured()
    if pricing is not None:snapshot['budget']['pricing']=pricing
    snapshot['events']=rows
    snapshot['dependency_files']=files
    snapshot['evidence_scope']={'status':'partial' if partial else 'bounded', 'window_seconds':30*86400,
        'hops':2, 'edge_types':['device_id'], 'rows':len(rows),'nodes':len(nodes),'bytes':byte_count,
        'limitations':['One shared-device neighborhood; not a complete connected component.',
                      'Auxiliary files are captured at projection time; historical validity is unverified.']}
    from .rag.store import index_metadata
    snapshot['knowledge_index_digest']=index_metadata().get('index_digest','')
    from .tools.capability import investigation_constraints
    from .tools.risk_knowledge import get_event_evidence
    with investigation_constraints(snapshot):
        event=snapshot['decision']['event']
        snapshot['event_evidence']=get_event_evidence(snapshot['decision'].get('business_event_id') or event['event_id'])
    snapshot['manifest']={'version':1,'captured_at':time.time(),'event_cutoff':anchor,'knowledge_cutoff':anchor,
        'events_hash':digest(rows),'event_evidence_hash':digest(snapshot['event_evidence']),
        'dependencies':{k:digest(v) if v is not None else None for k,v in files.items()},
        'knowledge_index_digest':snapshot['knowledge_index_digest'],
        'policy_activation_id':snapshot['decision'].get('policy_activation_id'),
        'feature_snapshot_id':snapshot['decision'].get('feature_snapshot_id'),
        'historical_dependency_status':'unverified'}
    snapshot['snapshot_id']=digest(snapshot)
    return snapshot
