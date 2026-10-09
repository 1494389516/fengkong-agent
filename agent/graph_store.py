"""Graph persistence, separated from online decisions by schema or SQLite file.

The legacy class name remains compatible; the configured backend owns connections.
"""
from .storage import postgres, begin_write, local_schema, table_names, order_column, json_text
import sqlite3
import time
from .tools.datasource import data_dir


class SQLiteGraphStore:
    def connect(self):
        if postgres():
            from .storage import connect
            return connect("graph")
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
        CREATE INDEX IF NOT EXISTS graph_scope_recorded
          ON observations(tenant,app,recorded_at DESC,evidence_id DESC);
        CREATE TABLE IF NOT EXISTS dirty_devices (
          tenant TEXT NOT NULL, app TEXT NOT NULL, device_id TEXT NOT NULL,
          entity_generation TEXT NOT NULL,
          PRIMARY KEY(tenant,app,device_id,entity_generation));
        """)
        columns={r[1] for r in db.execute('PRAGMA table_info(dirty_devices)')}
        for name in ('dirty_since','scheduled_at'):
            if name not in columns:
                try:
                    db.execute('ALTER TABLE dirty_devices ADD COLUMN '+name+' REAL NOT NULL DEFAULT 0')
                except sqlite3.OperationalError:
                    if name not in {r[1] for r in db.execute('PRAGMA table_info(dirty_devices)')}:
                        raise
        db.execute('CREATE INDEX IF NOT EXISTS dirty_queue ON dirty_devices(scheduled_at)')
        return db

    def append(self,observation):
        db=self.connect()
        try:
            db.execute('INSERT INTO observations VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING',
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

    def latest_recorded_at(self,tenant,app):
        db=self.connect()
        try:
            row=db.execute("SELECT MAX(recorded_at) FROM observations WHERE tenant=? AND app=?",
                           (tenant,app)).fetchone()
            return row[0]
        finally: db.close()

    def devices_for_uid(self,tenant,app,uid):
        if not uid:
            return []
        db=self.connect()
        try:
            return db.execute("""SELECT DISTINCT device_id,entity_generation FROM observations
                WHERE tenant=? AND app=? AND uid=?""",(tenant,app,uid)).fetchall()
        finally: db.close()

    def mark_scope_dirty(self,tenant,app):
        """Conservative dependency closure, persisted without loading all rows."""
        db=self.connect()
        try:
            db.execute('INSERT INTO dirty_devices\n                (tenant,app,device_id,entity_generation,dirty_since,scheduled_at)\n                SELECT DISTINCT tenant,app,device_id,entity_generation,?,?\n                FROM observations WHERE tenant=? AND app=? ON CONFLICT DO NOTHING',(time.time(),time.time(),tenant,app))
            db.commit()
        finally: db.close()

    def mark_dirty(self,tenant,app,devices):
        if not devices:
            return
        db=self.connect()
        try:
            now=time.time()
            db.executemany('INSERT INTO dirty_devices\n                (tenant,app,device_id,entity_generation,dirty_since,scheduled_at) VALUES (?,?,?,?,?,?) ON CONFLICT DO NOTHING',
                           ((tenant,app,device,generation,now,now) for device,generation in sorted(devices)))
            db.commit()
        finally: db.close()

    def dirty_devices(self,limit):
        db=self.connect()
        try:
            return db.execute("""SELECT tenant,app,device_id,entity_generation
                FROM dirty_devices ORDER BY scheduled_at,"""+order_column(db)+" LIMIT ?",
                (limit,)).fetchall()
        finally: db.close()

    def defer_dirty(self,tenant,app,devices):
        db=self.connect()
        try:
            db.executemany("""UPDATE dirty_devices SET scheduled_at=?
                WHERE tenant=? AND app=? AND device_id=? AND entity_generation=?""",
                ((time.time(),tenant,app,d,g) for d,g in devices))
            db.commit()
        finally: db.close()

    def dirty_stats(self,*,now=None):
        db=self.connect()
        try:
            count,oldest=db.execute('SELECT COUNT(*),MIN(dirty_since) FROM dirty_devices').fetchone()
            anchor=time.time() if now is None else now
            return {'pending':count,'oldest_pending_age_seconds':max(0,anchor-oldest) if count else 0}
        finally: db.close()

    def clear_dirty(self,tenant,app,device,generation):
        db=self.connect()
        try:
            from .storage import guard_projection
            begin_write(db)
            guard_projection(db)
            db.execute("""DELETE FROM dirty_devices WHERE tenant=? AND app=?
                AND device_id=? AND entity_generation=?""",(tenant,app,device,generation))
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally: db.close()


def graph_store():
    return SQLiteGraphStore()
