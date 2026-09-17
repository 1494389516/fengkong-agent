"""Single-host transactional decision/event/outbox store.

SQLite is the authority; JSONL exports are recoverable projections. A writer
transaction fixes the visible event prefix and commits the decision with it.
This deliberately serializes local writers; it is not a distributed backend.
"""
import hashlib
import json
import sqlite3
import time
import uuid
from contextlib import contextmanager

from .datasource import data_dir, event_snapshot
from .idemp_store import IdempotencyConflict


def connect(*, _migration=False):
    legacy = data_dir() / "decide_idemp.json"
    if legacy.exists() and not _migration:
        from .idemp_store import _load
        if _load():
            raise RuntimeError("legacy idempotency migration required before online activation")
    path = data_dir() / "online.sqlite3"
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=10)
    # WAL is persistent; only initialize under the cross-process file lock.
    from .datasource import file_lock
    with file_lock(path):
        db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    db.executescript('''
        CREATE TABLE IF NOT EXISTS decisions (
            tenant TEXT, app TEXT, event_id TEXT, fingerprint TEXT NOT NULL,
            decision_id TEXT UNIQUE NOT NULL, record TEXT NOT NULL,
            PRIMARY KEY(tenant, app, event_id));
        CREATE TABLE IF NOT EXISTS events (
            tenant TEXT, app TEXT, event_id TEXT, occurred_at REAL,
            recorded_at REAL, body TEXT NOT NULL,
            PRIMARY KEY(tenant, app, event_id));
        CREATE TABLE IF NOT EXISTS outbox (
            decision_id TEXT PRIMARY KEY, body TEXT NOT NULL, exported INTEGER DEFAULT 0);
    ''')
    return db


def _fault(stage):
    """Fault-injection seam; no production behavior."""


def decide(event, operator, compute, *, scope, source_kind, received_at, prepare=None):
    tenant, app = scope
    if not all(isinstance(v, str) and v.strip() for v in scope):
        raise ValueError("authenticated tenant/app required")
    if source_kind not in ("business", "legacy_client"):
        raise ValueError("SDK reports are not business events")
    serialized = json.dumps(event, sort_keys=True, ensure_ascii=False, allow_nan=False)
    fingerprint = hashlib.sha256((source_kind + serialized).encode()).hexdigest()
    key = (tenant, app, event["event_id"])
    db = connect()
    try:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT fingerprint, record FROM decisions WHERE tenant=? AND app=? AND event_id=?", key).fetchone()
        if row:
            if row[0] != fingerprint:
                raise IdempotencyConflict("event_id 已用于不同请求体")
            db.rollback()
            return json.loads(row[1]), True
        received_at = time.time() if received_at is None else received_at
        evaluation = dict(prepare(dict(event), db) if prepare is not None else event)
        evaluation.update(tenant_id=tenant, app_id=app, received_at=received_at, recorded_at=received_at,
                          occurred_at=event["ts"], source_kind=source_kind)
        if source_kind == "legacy_client":
            evaluation["_source_ts"] = event["ts"]
            evaluation["ts"] = received_at
        history = [json.loads(r[0]) for r in db.execute(
            "SELECT body FROM events WHERE tenant=? AND app=? AND recorded_at<=? ORDER BY occurred_at, event_id",
            (tenant, app, received_at))]
        snapshot_id = hashlib.sha256(json.dumps(history, sort_keys=True).encode()).hexdigest()
        with event_snapshot(history, (str(data_dir()), tenant, app, snapshot_id)):
            record = dict(compute(evaluation, operator))
        record.update(decision_id=str(uuid.uuid4()), tenant_id=tenant, app_id=app,
                      business_event_id=event["event_id"], feature_snapshot_id=snapshot_id,
                      event=evaluation, approver=operator, evaluated_at=time.time())
        blob = json.dumps(record, ensure_ascii=False, allow_nan=False)
        db.execute("INSERT INTO decisions VALUES (?,?,?,?,?,?)", (*key, fingerprint, record["decision_id"], blob))
        _fault("after_decision")
        db.execute("INSERT INTO events VALUES (?,?,?,?,?,?)", (*key, evaluation["ts"], received_at,
                   json.dumps(evaluation, ensure_ascii=False, allow_nan=False)))
        _fault("after_event")
        db.execute("INSERT INTO outbox(decision_id,body) VALUES (?,?)", (record["decision_id"], blob))
        _fault("before_commit")
        db.commit()
        _fault("after_commit")
        return record, False
    except BaseException:
        db.rollback()
        raise
    finally:
        db.close()


def export_outbox(log_path):
    """Idempotent local JSONL projection, retried after failures and replays."""
    from .datasource import atomic_write_text, file_lock
    db = connect()
    try:
        rows = db.execute("SELECT decision_id,body FROM outbox WHERE exported=0").fetchall()
        for decision_id, body in rows:
            record = json.loads(body)
            lineage = {**record, "decision": record.get("action"),
                       "uid": record["event"].get("uid"), "event_id": record["business_event_id"]}
            for path, item in ((log_path, record), (data_dir() / "decision_lineage.jsonl", lineage)):
                with file_lock(path):
                    lines = path.read_text().splitlines() if path.exists() else []
                    # A damaged projection is an error, never silently reset.
                    existing = {json.loads(line).get("decision_id") for line in lines if line.strip()}
                    if decision_id not in existing:
                        lines.append(json.dumps(item, ensure_ascii=False))
                        atomic_write_text(path, "\n".join(lines) + "\n")
            db.execute("UPDATE outbox SET exported=1 WHERE decision_id=?", (decision_id,))
            db.commit()
    finally:
        db.close()


def migrate_legacy(tenant, app, mapping_path):
    """Offline migration: stop legacy writers; explicitly map hashed keys to source events.

    No missing events or fingerprints are invented. Existing completed public
    decisions are retained; conflicting or in-flight records abort the migration.
    """
    from pathlib import Path
    from .datasource import file_lock
    from .idemp_store import event_key
    if not all(isinstance(v,str) and v.strip() for v in (tenant,app)):
        raise ValueError("tenant/app required")
    legacy = data_dir() / "decide_idemp.json"
    mapping = json.loads(Path(mapping_path).read_text())
    with file_lock(legacy):
        records = json.loads(legacy.read_text())
        if not isinstance(records,dict) or set(records) != set(mapping):
            raise ValueError("mapping must account for every legacy record")
        db = connect(_migration=True)
        try:
            db.execute("BEGIN IMMEDIATE")
            for key, old in records.items():
                item = mapping[key]; event=item["event"]; source=item["source_kind"]
                if old.get("status") != "done" or not isinstance(old.get("public"),dict):
                    raise ValueError("in-flight or malformed legacy record")
                if event_key(event["event_id"]) != key or source not in ("business","legacy_client"):
                    raise ValueError("legacy event mapping mismatch")
                completed=old.get("completed_at")
                if type(completed) not in (int,float) or not __import__('math').isfinite(completed):
                    raise ValueError("legacy knowledge time unavailable")
                serialized=json.dumps(event,sort_keys=True,ensure_ascii=False,allow_nan=False)
                fp=hashlib.sha256((source+serialized).encode()).hexdigest()
                identity=(tenant,app,event["event_id"])
                prior=db.execute("SELECT fingerprint,record FROM decisions WHERE tenant=? AND app=? AND event_id=?",identity).fetchone()
                if prior:
                    existing=json.loads(prior[1])
                    if (prior[0]!=fp or existing.get("migration",{}).get("legacy_key")!=key
                            or any(existing.get(k)!=v for k,v in old["public"].items())):
                        raise IdempotencyConflict("migration conflicts with existing event")
                    continue
                evaluation={**event,"tenant_id":tenant,"app_id":app,"received_at":completed,
                            "recorded_at":completed,"occurred_at":event["ts"],"source_kind":source}
                if source=="legacy_client":evaluation.update(_source_ts=event["ts"],ts=completed)
                record={**old["public"],"decision_id":str(uuid.uuid4()),"tenant_id":tenant,"app_id":app,
                        "business_event_id":event["event_id"],"event":evaluation,"evaluated_at":completed,
                        "migration":{"source":"decide_idemp.json","legacy_key":key,
                                     "legacy_input_fingerprint":old.get("input_fingerprint")}}
                blob=json.dumps(record,ensure_ascii=False,allow_nan=False)
                db.execute("INSERT INTO decisions VALUES (?,?,?,?,?,?)",(*identity,fp,record["decision_id"],blob))
                db.execute("INSERT INTO events VALUES (?,?,?,?,?,?)",(*identity,evaluation["ts"],completed,json.dumps(evaluation,allow_nan=False)))
                db.execute("INSERT INTO outbox(decision_id,body) VALUES (?,?)",(record["decision_id"],blob))
            db.commit()
            # A crash before rename is safe: rerunning compares all fingerprints.
            archive=legacy.with_name("decide_idemp.migrated."+hashlib.sha256(legacy.read_bytes()).hexdigest()+".json")
            legacy.replace(archive)
            return {"migrated":len(records),"archive":str(archive)}
        except BaseException:
            db.rollback();raise
        finally:db.close()


def main():
    import argparse
    p=argparse.ArgumentParser(description="Offline legacy idempotency migration; stop old writers first")
    p.add_argument("command",choices=["migrate-legacy"])
    p.add_argument("--tenant",required=True);p.add_argument("--app",required=True)
    p.add_argument("--mapping",required=True)
    args=p.parse_args()
    print(json.dumps(migrate_legacy(args.tenant,args.app,args.mapping)))

if __name__=="__main__":main()
