"""Durable local event-bus boundary with claim/lease/dead-letter semantics.

LocalEventBus remains a single-host adapter backed by SQLite. Consumers must claim
work before processing; acknowledgements are fenced by lease token. Production can
replace this adapter with Kafka/Pulsar without changing Collector or consumers.
"""
from dataclasses import dataclass
import json
import sqlite3
import time
import uuid

from .tools.online_store import connect


@dataclass(frozen=True)
class Event:
    event_id: str
    topic: str
    key: str
    payload: dict
    created_at: float


@dataclass(frozen=True)
class ClaimedEvent(Event):
    lease_token: str
    attempts: int


class LocalEventBus:
    def _ensure(self, db):
        db.execute("""CREATE TABLE IF NOT EXISTS integration_events (
            event_id TEXT PRIMARY KEY,
            topic TEXT NOT NULL,
            event_key TEXT NOT NULL,
            payload TEXT NOT NULL,
            created_at REAL NOT NULL,
            published INTEGER NOT NULL DEFAULT 0,
            attempts INTEGER NOT NULL DEFAULT 0,
            lease_token TEXT,
            lease_until REAL,
            last_error TEXT
        )""")
        # Online migration for the pre-lease schema; each ALTER is additive.
        columns={row[1] for row in db.execute("PRAGMA table_info(integration_events)")}
        additions={
            "attempts":"INTEGER NOT NULL DEFAULT 0",
            "lease_token":"TEXT",
            "lease_until":"REAL",
            "last_error":"TEXT",
        }
        for name,ddl in additions.items():
            if name not in columns:
                try:
                    db.execute("ALTER TABLE integration_events ADD COLUMN %s %s" % (name,ddl))
                except sqlite3.OperationalError as exc:
                    # Another process may have completed the same additive migration
                    # after our PRAGMA snapshot. Re-read; only that race is benign.
                    refreshed={row[1] for row in db.execute("PRAGMA table_info(integration_events)")}
                    if name not in refreshed:
                        raise
        db.execute("""CREATE INDEX IF NOT EXISTS integration_events_pending
                      ON integration_events(published,created_at,event_id)""")
        db.execute("""CREATE INDEX IF NOT EXISTS integration_events_claim
                      ON integration_events(topic,published,lease_until,created_at,event_id)""")

    @staticmethod
    def _validate_limit(limit):
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("limit must be 1..1000")

    def publish(self, topic, key, payload, *, connection=None):
        if not isinstance(topic,str) or not topic or not isinstance(key,str) or not key or not isinstance(payload,dict):
            raise ValueError("topic, key and dict payload required")
        owned=connection is None
        db=connection or connect()
        try:
            self._ensure(db)
            event=Event(uuid.uuid4().hex,topic,key,dict(payload),time.time())
            db.execute("""INSERT INTO integration_events
                (event_id,topic,event_key,payload,created_at,published,attempts)
                VALUES (?,?,?,?,?,0,0)""",
                (event.event_id,event.topic,event.key,
                 json.dumps(event.payload,ensure_ascii=False,allow_nan=False),
                 event.created_at))
            if owned: db.commit()
            return event
        except BaseException:
            if owned: db.rollback()
            raise
        finally:
            if owned: db.close()

    def claim(self, topic, *, limit=100, lease_seconds=30.0, max_attempts=5, now=None):
        self._validate_limit(limit)
        if not isinstance(topic,str) or not topic:
            raise ValueError("topic must be a non-empty string")
        if type(lease_seconds) not in (int,float) or lease_seconds <= 0:
            raise ValueError("positive lease_seconds required")
        if type(max_attempts) is not int or max_attempts < 1:
            raise ValueError("positive max_attempts required")
        anchor=time.time() if now is None else float(now)
        db=connect()
        try:
            self._ensure(db)
            db.commit()  # schema migration must finish before the claim transaction
            db.execute("BEGIN IMMEDIATE")
            # Exhausted, currently-unleased poison messages become dead letters.
            db.execute("""UPDATE integration_events
                SET published=-1,last_error=COALESCE(last_error,'max_attempts_exhausted')
                WHERE topic=? AND published=0 AND attempts>=?
                  AND (lease_until IS NULL OR lease_until<=?)""",
                (topic,max_attempts,anchor))
            rows=db.execute("""SELECT event_id,topic,event_key,payload,created_at,attempts
                FROM integration_events
                WHERE topic=? AND published=0 AND attempts<?
                  AND (lease_until IS NULL OR lease_until<=?)
                ORDER BY created_at,event_id LIMIT ?""",
                (topic,max_attempts,anchor,limit)).fetchall()
            claimed=[]
            for row in rows:
                token=uuid.uuid4().hex
                attempts=int(row[5])+1
                changed=db.execute("""UPDATE integration_events
                    SET attempts=?,lease_token=?,lease_until=?,last_error=NULL
                    WHERE event_id=? AND published=0
                      AND (lease_until IS NULL OR lease_until<=?)""",
                    (attempts,token,anchor+float(lease_seconds),row[0],anchor)).rowcount
                if changed:
                    claimed.append(ClaimedEvent(
                        row[0],row[1],row[2],json.loads(row[3]),row[4],token,attempts))
            db.commit()
            return claimed
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def acknowledge(self, event_id, lease_token):
        if not lease_token:
            raise ValueError("lease_token required")
        db=connect()
        try:
            self._ensure(db)
            changed=db.execute("""UPDATE integration_events
                SET published=1,lease_token=NULL,lease_until=NULL,last_error=NULL
                WHERE event_id=? AND published=0 AND lease_token=? AND lease_until>?""",
                (event_id,lease_token,time.time())).rowcount
            db.commit()
            return changed==1
        finally:
            db.close()

    def fail(self, event_id, lease_token, error, *, max_attempts=5):
        if not lease_token:
            raise ValueError("lease_token required")
        db=connect()
        try:
            self._ensure(db)
            row=db.execute("""SELECT attempts FROM integration_events
                WHERE event_id=? AND published=0 AND lease_token=? AND lease_until>?""",
                (event_id,lease_token,time.time())).fetchone()
            if row is None:
                return False
            exhausted=int(row[0])>=max_attempts
            changed=db.execute("""UPDATE integration_events
                SET published=?,lease_token=NULL,lease_until=NULL,last_error=?
                WHERE event_id=? AND published=0 AND lease_token=? AND lease_until>?""",
                (-1 if exhausted else 0,str(error)[:1000],event_id,lease_token,time.time())).rowcount
            db.commit()
            return changed==1
        finally:
            db.close()

    def pending(self, *, limit=100, topic=None):
        """Diagnostic view; consumers must use claim(), never pending()."""
        self._validate_limit(limit)
        db=connect()
        try:
            self._ensure(db)
            if topic is None:
                rows=db.execute("""SELECT event_id,topic,event_key,payload,created_at
                    FROM integration_events WHERE published=0
                    ORDER BY created_at,event_id LIMIT ?""",(limit,)).fetchall()
            else:
                rows=db.execute("""SELECT event_id,topic,event_key,payload,created_at
                    FROM integration_events WHERE published=0 AND topic=?
                    ORDER BY created_at,event_id LIMIT ?""",(topic,limit)).fetchall()
            return [Event(row[0],row[1],row[2],json.loads(row[3]),row[4]) for row in rows]
        finally:
            db.close()

    def stats(self, *, topic=None, now=None):
        anchor=time.time() if now is None else float(now)
        db=connect()
        try:
            self._ensure(db)
            where=""
            params=[]
            if topic is not None:
                if not isinstance(topic,str) or not topic:
                    raise ValueError("topic must be a non-empty string")
                where=" AND topic=?";params.append(topic)
            pending,leased,oldest,max_attempts=db.execute("""
                SELECT COUNT(*),
                       COALESCE(SUM(CASE WHEN lease_until>? THEN 1 ELSE 0 END),0),
                       MIN(created_at),COALESCE(MAX(attempts),0)
                FROM integration_events WHERE published=0"""+where,
                [anchor,*params]).fetchone()
            dead=db.execute("SELECT COUNT(*) FROM integration_events WHERE published=-1"+where,
                            params).fetchone()[0]
            ready=pending-leased
            return {
                "topic":topic,
                "pending":pending,
                "ready":ready,
                "leased":leased,
                "dead_letters":dead,
                "oldest_pending_age_seconds":
                    (max(0.0,anchor-oldest) if oldest is not None else 0.0),
                "max_attempts":max_attempts,
            }
        finally:
            db.close()

    def dead_letters(self, *, limit=100, topic=None):
        self._validate_limit(limit)
        db=connect()
        try:
            self._ensure(db)
            sql="""SELECT event_id,topic,event_key,payload,created_at,last_error,attempts
                   FROM integration_events WHERE published=-1"""
            params=[]
            if topic is not None:
                sql+=" AND topic=?";params.append(topic)
            sql+=" ORDER BY created_at,event_id LIMIT ?";params.append(limit)
            return [{"event":Event(r[0],r[1],r[2],json.loads(r[3]),r[4]),
                     "last_error":r[5],"attempts":r[6]}
                    for r in db.execute(sql,params).fetchall()]
        finally:
            db.close()


def event_bus():
    return LocalEventBus()
