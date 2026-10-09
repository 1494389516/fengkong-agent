"""Online feature-store boundary for server-computed risk intelligence."""
import json
import math
import sqlite3
import time
import uuid
from .storage import postgres, begin_write, guard_projection
from .tools.datasource import data_dir


def _time_value(value):
    try:
        if type(value) not in (int,float) or value<0 or not math.isfinite(value):
            raise ValueError('nonnegative finite time value required')
        return float(value)
    except OverflowError as exc:
        raise ValueError('time value out of range') from exc


class SQLiteOnlineFeatureStore:
    def connect(self):
        if postgres():
            from .storage import connect
            return connect('features')
        path=data_dir()/"features.sqlite3"
        path.parent.mkdir(parents=True,exist_ok=True)
        db=sqlite3.connect(path,timeout=10)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("""CREATE TABLE IF NOT EXISTS entity_features (
          tenant TEXT NOT NULL, app TEXT NOT NULL, entity_type TEXT NOT NULL,
          entity_id TEXT NOT NULL, generation TEXT NOT NULL, feature_set TEXT NOT NULL,
          body TEXT NOT NULL, computed_at REAL NOT NULL,
          PRIMARY KEY(tenant,app,entity_type,entity_id,generation,feature_set))""")
        if 'refresh_pending' not in {r[1] for r in db.execute('PRAGMA table_info(entity_features)')}:
            try:
                db.execute('ALTER TABLE entity_features ADD COLUMN refresh_pending INTEGER NOT NULL DEFAULT 0')
            except sqlite3.OperationalError:
                if 'refresh_pending' not in {r[1] for r in db.execute('PRAGMA table_info(entity_features)')}:
                    raise
        db.execute('''CREATE TABLE IF NOT EXISTS feature_versions(
            revision TEXT PRIMARY KEY,tenant TEXT,app TEXT,entity_type TEXT,entity_id TEXT,
            generation TEXT,feature_set TEXT,body TEXT,computed_at REAL)''')
        return db

    def put(self,tenant,app,entity_type,entity_id,generation,feature_set,body,*,computed_at=None):
        return self.put_many(tenant,app,entity_type,entity_id,generation,
                             {feature_set:body},computed_at=computed_at)

    def put_many(self,tenant,app,entity_type,entity_id,generation,values,*,computed_at=None):
        if not values or any(not isinstance(body,dict) for body in values.values()):
            raise ValueError("feature bodies must be dicts")
        stamp=_time_value(time.time() if computed_at is None else computed_at)
        if stamp==0:
            raise ValueError('zero timestamp is reserved for invalidation')
        db=self.connect()
        try:
            begin_write(db)
            guard_projection(db)
            revision=uuid.uuid4().hex
            for feature_set,body in values.items():
                version=revision+':'+feature_set
                raw=json.dumps({**body,'feature_revision':version},ensure_ascii=False,allow_nan=False)
                key=(tenant,app,entity_type,entity_id,generation,feature_set)
                db.execute('INSERT INTO feature_versions VALUES(?,?,?,?,?,?,?,?,?)', (version,*key,raw,stamp))
                db.execute("""INSERT INTO entity_features
                  (tenant,app,entity_type,entity_id,generation,feature_set,body,computed_at,refresh_pending)
                  VALUES (?,?,?,?,?,?,?,?,0)
                  ON CONFLICT(tenant,app,entity_type,entity_id,generation,feature_set)
                  DO UPDATE SET body=excluded.body,computed_at=excluded.computed_at,refresh_pending=0""",
                  (*key,raw,stamp))
            db.commit()
            return revision
        except BaseException:
            db.rollback()
            raise
        finally: db.close()

    def get(self,tenant,app,entity_type,entity_id,generation,feature_set,*,max_age=None,now=None,allow_previous=False):
        if max_age is not None: max_age=_time_value(max_age)
        if now is not None: now=_time_value(now)
        db=self.connect()
        try:
            row=db.execute("""SELECT body,computed_at,refresh_pending FROM entity_features
              WHERE tenant=? AND app=? AND entity_type=? AND entity_id=? AND generation=? AND feature_set=?""",
              (tenant,app,entity_type,entity_id,generation,feature_set)).fetchone()
            if not row:return None
            if row[2] and (not allow_previous or max_age is None):return None
            anchor=_time_value(time.time() if now is None else now)
            try:
                stamp=_time_value(row[1])
            except ValueError:
                return None  # Legacy malformed timestamps must not look current.
            if stamp==0 or stamp>anchor:return None
            if max_age is not None and anchor-stamp>max_age:return None
            result=json.loads(row[0]);result["feature_computed_at"]=row[1]
            result['feature_refresh_status']='refreshing' if row[2] else 'current'
            return result
        finally:db.close()

    def availability_stats(self,*,now=None,max_age=300):
        anchor=_time_value(time.time() if now is None else now)
        max_age=_time_value(max_age)
        db=self.connect()
        try:
            valid_type="" if postgres(db) else "typeof(computed_at) IN ('real','integer') AND "
            complete="COALESCE((body::jsonb->>'truncated')::boolean,false)=false" if postgres(db) else "COALESCE(json_extract(body,'$.truncated'),0)=0"
            total,available=db.execute("""SELECT COUNT(*),COALESCE(SUM(CASE
                WHEN """+valid_type+"""computed_at>0 AND refresh_pending=0
                AND computed_at>=? AND computed_at<=? AND """+complete+"""
                THEN 1 ELSE 0 END),0) FROM entity_features WHERE entity_type='device'
                AND feature_set='graph_risk_v1'""",(anchor-max_age,anchor)).fetchone()
            return {'total':total,'available':available,'unavailable':total-available,
                    'availability':available/total if total else 1.0}
        finally: db.close()

    def invalidate_scope(self,tenant,app):
        db=self.connect()
        try:
            begin_write(db)
            guard_projection(db)
            db.execute("""UPDATE entity_features SET refresh_pending=1
                WHERE tenant=? AND app=? AND entity_type='device'
                AND feature_set IN ('graph_risk_v1','graph_risk_shadow_v1')""",(tenant,app))
            db.commit()
        finally: db.close()

    def invalidate_devices(self,tenant,app,devices):
        if not devices:
            return
        db=self.connect()
        try:
            begin_write(db)
            guard_projection(db)
            db.executemany("""UPDATE entity_features SET refresh_pending=1
                WHERE tenant=? AND app=? AND entity_type='device'
                  AND entity_id=? AND generation=? AND feature_set IN (?,?)""",
                ((tenant,app,device,generation,'graph_risk_v1','graph_risk_shadow_v1')
                 for device,generation in devices))
            db.commit()
        finally: db.close()


def online_feature_store():
    return SQLiteOnlineFeatureStore()
