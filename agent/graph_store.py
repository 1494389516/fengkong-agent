"""Graph persistence boundary.

The default backend is a dedicated SQLite database, deliberately separate from
the online decision/event authority. A production graph database can replace this
adapter without changing graph algorithms or Decision enrichment.
"""
import sqlite3
from .tools.datasource import data_dir


class SQLiteGraphStore:
    def connect(self):
        path=data_dir()/"graph.sqlite3"
        path.parent.mkdir(parents=True,exist_ok=True)
        db=sqlite3.connect(path,timeout=10)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        db.executescript("""
        CREATE TABLE IF NOT EXISTS observations (
          evidence_id TEXT PRIMARY KEY, tenant TEXT NOT NULL, app TEXT NOT NULL,
          uid TEXT, device_id TEXT NOT NULL, entity_generation TEXT NOT NULL,
          ip TEXT, observed_at REAL NOT NULL, recorded_at REAL NOT NULL);
        CREATE INDEX IF NOT EXISTS graph_device_time
          ON observations(tenant,app,device_id,entity_generation,observed_at);
        CREATE INDEX IF NOT EXISTS graph_uid_time
          ON observations(tenant,app,uid,observed_at);
        """)
        return db

    def append(self,observation):
        db=self.connect()
        try:
            db.execute("""INSERT OR IGNORE INTO observations VALUES (?,?,?,?,?,?,?,?,?)""",
              (observation["evidence_id"],observation["tenant_id"],observation["app_id"],
               observation.get("uid"),observation["device_id"],observation["entity_generation"],
               observation.get("ip"),observation["observed_at"],observation["recorded_at"]))
            db.commit()
        finally: db.close()

    def scope_rows(self,tenant,app,as_of,limit=5000):
        db=self.connect()
        try:
            rows=db.execute("""SELECT evidence_id,uid,device_id,entity_generation,ip,observed_at,recorded_at
              FROM observations WHERE tenant=? AND app=? AND recorded_at<=?
              ORDER BY recorded_at DESC,evidence_id DESC LIMIT ?""",(tenant,app,as_of,limit+1)).fetchall()
            truncated=len(rows)>limit
            return rows[:limit],truncated
        finally: db.close()


def graph_store():
    return SQLiteGraphStore()
