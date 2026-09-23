"""Durable event-bus boundary for Collector/Decision -> asynchronous consumers.

LocalEventBus is intentionally a single-host implementation backed by the existing
SQLite outbox. Production deployments replace this adapter with Kafka/Pulsar
without coupling request handlers or Agent code to a broker client.
"""
from dataclasses import dataclass
import json
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


class LocalEventBus:
    def _ensure(self, db):
        db.execute("""CREATE TABLE IF NOT EXISTS integration_events (
            event_id TEXT PRIMARY KEY,
            topic TEXT NOT NULL,
            event_key TEXT NOT NULL,
            payload TEXT NOT NULL,
            created_at REAL NOT NULL,
            published INTEGER NOT NULL DEFAULT 0
        )""")
        db.execute("""CREATE INDEX IF NOT EXISTS integration_events_pending
                      ON integration_events(published, created_at, event_id)""")

    def publish(self, topic, key, payload, *, connection=None):
        if not topic or not key or not isinstance(payload, dict):
            raise ValueError("topic, key and dict payload required")
        owned = connection is None
        db = connection or connect()
        try:
            self._ensure(db)
            event = Event(uuid.uuid4().hex, topic, key, dict(payload), time.time())
            db.execute(
                "INSERT INTO integration_events VALUES (?,?,?,?,?,0)",
                (event.event_id, event.topic, event.key,
                 json.dumps(event.payload, ensure_ascii=False, allow_nan=False),
                 event.created_at),
            )
            if owned:
                db.commit()
            return event
        except BaseException:
            if owned:
                db.rollback()
            raise
        finally:
            if owned:
                db.close()

    def pending(self, *, limit=100):
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("limit must be 1..1000")
        db = connect()
        try:
            self._ensure(db)
            rows = db.execute(
                "SELECT event_id,topic,event_key,payload,created_at "
                "FROM integration_events WHERE published=0 "
                "ORDER BY created_at,event_id LIMIT ?", (limit,)
            ).fetchall()
            return [Event(row[0], row[1], row[2], json.loads(row[3]), row[4]) for row in rows]
        finally:
            db.close()

    def acknowledge(self, event_id):
        db = connect()
        try:
            self._ensure(db)
            changed = db.execute(
                "UPDATE integration_events SET published=1 WHERE event_id=? AND published=0",
                (event_id,),
            ).rowcount
            db.commit()
            return changed == 1
        finally:
            db.close()


def event_bus():
    # Stable seam for a future KafkaEventBus/PulsarEventBus selected by deployment.
    return LocalEventBus()
