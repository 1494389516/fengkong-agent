"""Bounded server-side graph risk projection fed by accepted SDK evidence.

This is risk intelligence, not an enforcement authority. It materializes only
server-bound identities and produces explainable graph features for Decision/Agent.
"""
import json
import math
import time

from .tools.online_store import connect

MAX_DEVICE_ACCOUNTS = 64
MAX_ACCOUNT_DEVICES = 64
MAX_DEVICE_IPS = 64


def _ensure(db):
    db.executescript("""
    CREATE TABLE IF NOT EXISTS graph_observations (
      evidence_id TEXT PRIMARY KEY,
      tenant TEXT NOT NULL,
      app TEXT NOT NULL,
      uid TEXT,
      device_id TEXT NOT NULL,
      entity_generation TEXT NOT NULL,
      ip TEXT,
      observed_at REAL NOT NULL,
      recorded_at REAL NOT NULL
    );
    CREATE INDEX IF NOT EXISTS graph_device_time
      ON graph_observations(tenant,app,device_id,entity_generation,observed_at);
    CREATE INDEX IF NOT EXISTS graph_uid_time
      ON graph_observations(tenant,app,uid,observed_at);
    CREATE TABLE IF NOT EXISTS graph_risk_projection (
      tenant TEXT NOT NULL,
      app TEXT NOT NULL,
      device_id TEXT NOT NULL,
      entity_generation TEXT NOT NULL,
      body TEXT NOT NULL,
      updated_at REAL NOT NULL,
      PRIMARY KEY(tenant,app,device_id,entity_generation)
    );
    """)


def _finite(value):
    return type(value) in (int, float) and math.isfinite(value)


def ingest_observation(observation, *, connection=None):
    required=("evidence_id","tenant_id","app_id","device_id","entity_generation",
              "observed_at","recorded_at")
    if not isinstance(observation,dict) or any(not observation.get(k) for k in required[:5]):
        raise ValueError("complete server-bound observation required")
    if observation.get("identity_trust")!="server_bound":
        raise ValueError("graph projection accepts server-bound identity only")
    if not _finite(observation.get("observed_at")) or not _finite(observation.get("recorded_at")):
        raise ValueError("finite graph timestamps required")
    owned=connection is None
    db=connection or connect()
    try:
        _ensure(db)
        db.execute("""INSERT OR IGNORE INTO graph_observations
          (evidence_id,tenant,app,uid,device_id,entity_generation,ip,observed_at,recorded_at)
          VALUES (?,?,?,?,?,?,?,?,?)""",
          (observation["evidence_id"],observation["tenant_id"],observation["app_id"],
           observation.get("uid"),observation["device_id"],observation["entity_generation"],
           observation.get("ip"),observation["observed_at"],observation["recorded_at"]))
        result=recompute_device(
            observation["tenant_id"],observation["app_id"],observation["device_id"],
            observation["entity_generation"],connection=db,as_of=observation["recorded_at"])
        if owned: db.commit()
        return result
    except BaseException:
        if owned: db.rollback()
        raise
    finally:
        if owned: db.close()


def recompute_device(tenant,app,device_id,generation,*,connection=None,as_of=None):
    owned=connection is None
    db=connection or connect()
    try:
        _ensure(db)
        anchor=time.time() if as_of is None else as_of
        rows=db.execute("""SELECT uid,ip,observed_at FROM graph_observations
          WHERE tenant=? AND app=? AND device_id=? AND entity_generation=?
            AND recorded_at<=? ORDER BY observed_at,evidence_id""",
          (tenant,app,device_id,generation,anchor)).fetchall()
        accounts=sorted({r[0] for r in rows if r[0]})[:MAX_DEVICE_ACCOUNTS]
        ips=sorted({r[1] for r in rows if r[1]})[:MAX_DEVICE_IPS]
        account_device_counts={}
        for uid in accounts:
            count=db.execute("""SELECT COUNT(DISTINCT device_id || ':' || entity_generation)
              FROM graph_observations WHERE tenant=? AND app=? AND uid=? AND recorded_at<=?""",
              (tenant,app,uid,anchor)).fetchone()[0]
            account_device_counts[uid]=min(int(count),MAX_ACCOUNT_DEVICES+1)
        shared=max(0,len(accounts)-1)
        churn=max(account_device_counts.values(),default=0)
        dense = len(accounts)>=3 and len(rows)>=max(6,len(accounts)*2)
        score=min(1.0, shared/5.0 + max(0,churn-2)/8.0 + (0.25 if dense else 0.0))
        result={
          "device_id":device_id,"entity_generation":generation,
          "account_count":len(accounts),"accounts":accounts,
          "ip_count":len(ips),"shared_account_count":shared,
          "max_account_device_churn":churn,
          "is_dense_subgraph":dense,
          "community_risk_density":round(score,6),
          "risk_tags":[tag for tag,hit in (
              ("shared_device",shared>0),("identity_churn",churn>2),("dense_subgraph",dense)) if hit],
          "interpretation":"association_features_only",
          "as_of":anchor,
        }
        db.execute("""INSERT INTO graph_risk_projection VALUES (?,?,?,?,?,?)
          ON CONFLICT(tenant,app,device_id,entity_generation)
          DO UPDATE SET body=excluded.body,updated_at=excluded.updated_at""",
          (tenant,app,device_id,generation,json.dumps(result,ensure_ascii=False,allow_nan=False),anchor))
        if owned: db.commit()
        return result
    finally:
        if owned: db.close()


def lookup(tenant,app,device_id,generation,*,connection=None):
    owned=connection is None
    db=connection or connect()
    try:
        _ensure(db)
        row=db.execute("""SELECT body FROM graph_risk_projection
          WHERE tenant=? AND app=? AND device_id=? AND entity_generation=?""",
          (tenant,app,device_id,generation)).fetchone()
        return json.loads(row[0]) if row else None
    finally:
        if owned: db.close()


def consume_pending(*,limit=100):
    from .event_bus import event_bus
    bus=event_bus(); processed=0; failed=[]
    for event in bus.pending(limit=limit):
        if event.topic!="risk.evidence.accepted":
            continue
        try:
            ingest_observation(event.payload)
            if bus.acknowledge(event.event_id): processed+=1
        except Exception as exc:
            failed.append({"event_id":event.event_id,"error":type(exc).__name__})
    return {"processed":processed,"failed":failed}
