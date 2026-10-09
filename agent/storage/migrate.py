"""Offline PostgreSQL provisioning and transactional import of stopped SQLite stores."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import time

from . import KINDS, SCHEMA_VERSION, database_url, namespace, schema, lock_key

FILES = {'online': 'online.sqlite3', 'agent': 'investigations.sqlite3',
         'graph': 'graph.sqlite3', 'features': 'features.sqlite3', 'knowledge': 'risk_knowledge.sqlite3'}
IMMUTABLE = {'online': ('evidence', 'report_receipts'),
             'agent': ('case_revisions', 'case_reviews', 'case_arbitrations')}
PROFILES = {
    'collector': {'online': {'report_receipts':'SELECT,INSERT', 'evidence':'SELECT,INSERT',
        'attestation_counters':'SELECT,INSERT,UPDATE', 'attestation_challenges':'SELECT,INSERT,UPDATE',
        'enrollment_evidence':'SELECT,INSERT', 'enrolled_attestation_keys':'SELECT,INSERT',
        'integration_events':'SELECT,INSERT'}},
    'runtime': {'online': {'*':'SELECT', 'decisions':'INSERT', 'events':'INSERT', 'outbox':'INSERT,UPDATE'},
                'features': {'*':'SELECT'}, 'graph':{'*':'SELECT'}, 'knowledge':{'*':'SELECT'}},
    'projector': {'online':{'*':'SELECT'}, 'knowledge':{'*':'SELECT'},
        'agent':{'*':'SELECT', 'cases':'INSERT,UPDATE', 'case_revisions':'INSERT',
                 'investigation_tasks':'INSERT', 'investigation_seen':'INSERT'}},
    'agent': {'online':{'*':'SELECT'}, 'knowledge':{'*':'SELECT'}, 'features':{'*':'SELECT'},
        'agent':{'*':'SELECT', 'investigation_tasks':'INSERT,UPDATE', 'investigation_runs':'INSERT,UPDATE',
                 'cases':'UPDATE', 'run_steps':'INSERT,UPDATE', 'run_contracts':'INSERT',
                 'budget_contracts':'INSERT', 'reservation_contracts':'INSERT',
                 'resource_receipts':'INSERT', 'budget_receipts':'INSERT,UPDATE'}},
    'reviewer': {'agent': {'*':'SELECT', 'case_reviews':'INSERT', 'case_arbitrations':'INSERT'}},
    'graph': {'online':{'integration_events':'SELECT,UPDATE', 'integration_receipts':'SELECT,INSERT,UPDATE'},
              'graph':{'*':'SELECT,INSERT,UPDATE,DELETE'}, 'features':{'*':'SELECT,INSERT,UPDATE,DELETE'}},
    'knowledge': {'knowledge':{'*':'SELECT,INSERT,UPDATE,DELETE'}},
}


def initialize(db, prefix):
    from psycopg import sql
    db.execute('SELECT pg_advisory_xact_lock(%s)', (lock_key(prefix+':migrate'),))
    for kind in KINDS:
        name = schema(kind, prefix)
        db.execute(sql.SQL('CREATE SCHEMA IF NOT EXISTS {}').format(sql.Identifier(name)))
        db.execute(sql.SQL('REVOKE ALL ON SCHEMA {} FROM PUBLIC').format(sql.Identifier(name)))
        db.execute(sql.SQL('SET LOCAL search_path TO {}, pg_catalog').format(sql.Identifier(name)))
        db.execute('CREATE TABLE IF NOT EXISTS storage_version(singleton BIGINT PRIMARY KEY CHECK(singleton=1), version BIGINT NOT NULL)')
        current = db.execute('SELECT version FROM storage_version WHERE singleton=1').fetchone()
        if current and current != (SCHEMA_VERSION,):
            raise RuntimeError('unsupported schema version; explicit upgrade required')
        db.execute((Path(__file__).parent/(kind+'.sql')).read_text())
        db.execute('INSERT INTO storage_version VALUES(1,%s) ON CONFLICT DO NOTHING', (SCHEMA_VERSION,))
        if kind in IMMUTABLE:
            db.execute("""CREATE OR REPLACE FUNCTION immutable_history() RETURNS trigger
                LANGUAGE plpgsql SET search_path=pg_catalog AS $$
                BEGIN RAISE EXCEPTION 'history is immutable'; END $$""")
            for table in IMMUTABLE[kind]:
                db.execute(sql.SQL('DROP TRIGGER IF EXISTS immutable_history ON {}').format(sql.Identifier(table)))
                db.execute(sql.SQL('CREATE TRIGGER immutable_history BEFORE UPDATE OR DELETE OR TRUNCATE ON {} '
                    'FOR EACH STATEMENT EXECUTE FUNCTION immutable_history()').format(sql.Identifier(table)))
    db.execute(sql.SQL('SET LOCAL search_path TO {}, pg_catalog').format(sql.Identifier(schema('agent',prefix))))
    db.execute('CREATE TABLE IF NOT EXISTS migration_imports(source_digest TEXT PRIMARY KEY,manifest TEXT NOT NULL)')


def grant_profile(db, prefix, role, profile):
    from psycopg import sql
    if profile not in PROFILES:
        raise ValueError('unknown database role profile')
    row=db.execute('SELECT rolsuper,rolcreaterole,rolcreatedb FROM pg_roles WHERE rolname=%s',(role,)).fetchone()
    if row is None or any(row):
        raise ValueError('service role must exist without superuser/role/database creation privileges')
    # Grants are additive; dedicated freshly provisioned service roles are required.
    for kind, tables in PROFILES[profile].items():
        name=schema(kind,prefix)
        db.execute(sql.SQL('GRANT USAGE ON SCHEMA {} TO {}').format(sql.Identifier(name),sql.Identifier(role)))
        db.execute(sql.SQL('GRANT SELECT ON {}.storage_version TO {}').format(sql.Identifier(name),sql.Identifier(role)))
        for table, privileges in tables.items():
            target=sql.SQL('ALL TABLES IN SCHEMA {}').format(sql.Identifier(name)) if table=='*' else sql.SQL('{}.{}').format(sql.Identifier(name),sql.Identifier(table))
            db.execute(sql.SQL('GRANT {} ON {} TO {}').format(sql.SQL(privileges), target, sql.Identifier(role)))
        if any('INSERT' in privilege for privilege in tables.values()):
            db.execute(sql.SQL('GRANT USAGE ON ALL SEQUENCES IN SCHEMA {} TO {}').format(sql.Identifier(name),sql.Identifier(role)))


def _sources():
    from ..tools.datasource import data_dir, agent_state_dir
    return {kind:(agent_state_dir() if kind=='agent' else data_dir())/filename for kind,filename in FILES.items()}


def import_sqlite(db, prefix, *, writers_stopped):
    from psycopg import sql
    if not writers_stopped:
        raise ValueError('stop all source writers and pass --writers-stopped before import')
    sources={};manifest={};fingerprint=hashlib.sha256()
    try:
        for kind,path in _sources().items():
            if not path.exists():continue
            source=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True)
            sources[kind]=source
            source.execute('BEGIN')
            if source.execute('PRAGMA quick_check').fetchone()!=('ok',):
                raise ValueError('source database failed integrity check: '+kind)
            tables=[r[0] for r in source.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
            target={r[0] for r in db.execute('SELECT table_name FROM information_schema.tables WHERE table_schema=%s',(schema(kind,prefix),))}
            if set(tables)-target:
                raise ValueError('unsupported legacy tables; migrate old investigations first: '+kind)
            manifest[kind]={}
            for table in tables:
                columns=[r[1] for r in source.execute('PRAGMA table_info("'+table+'")')]
                if 'lease_until' in columns and source.execute('SELECT 1 FROM "'+table+'" WHERE lease_until>? LIMIT 1',(time.time(),)).fetchone():
                    raise ValueError('live source leases must expire before import')
                digest=hashlib.sha256();count=0
                for row in source.execute('SELECT * FROM "'+table+'" ORDER BY rowid'):
                    raw=json.dumps(row,ensure_ascii=False,allow_nan=False,default=lambda b:{'bytes':bytes(b).hex()})
                    digest.update((raw+'\n').encode());count+=1
                manifest[kind][table]={'count':count,'sha256':digest.hexdigest(),'columns':columns}
        fingerprint.update(json.dumps(manifest,sort_keys=True).encode())
        key=fingerprint.hexdigest()
        metadata=sql.Identifier(schema('agent',prefix),'migration_imports')
        old=db.execute(sql.SQL('SELECT manifest FROM {} WHERE source_digest=%s').format(metadata),(key,)).fetchone()
        if old:return {'replayed':True,'source_digest':key,'manifest':json.loads(old[0])}
        if db.execute(sql.SQL('SELECT 1 FROM {} LIMIT 1').format(metadata)).fetchone():
            raise ValueError('a different source was already imported into this namespace')
        # Reject mixed old/new deployment data, including tables absent in source.
        for kind in KINDS:
            for (table,) in db.execute('SELECT table_name FROM information_schema.tables WHERE table_schema=%s',(schema(kind,prefix),)):
                if table in ('storage_version','projection_cursor','projection_epoch','migration_imports'):continue
                if db.execute(sql.SQL('SELECT 1 FROM {} LIMIT 1').format(sql.Identifier(schema(kind,prefix),table))).fetchone():
                    raise ValueError('import requires an empty target namespace')
        for kind,source in sources.items():
            for table,details in manifest[kind].items():
                columns=details['columns']
                target=sql.Identifier(schema(kind,prefix),table)
                if table=='projection_cursor':
                    db.execute(sql.SQL('DELETE FROM {}').format(target))
                ordered=table in ('cases','investigation_tasks','outbox','dirty_devices')
                names=(['insertion_order'] if ordered else [])+columns
                query=sql.SQL('INSERT INTO {} ({}) VALUES ({})').format(target,
                    sql.SQL(',').join(map(sql.Identifier,names)),sql.SQL(',').join(sql.Placeholder()*len(names)))
                for row in source.execute('SELECT '+('rowid,' if ordered else '')+'* FROM "'+table+'" ORDER BY rowid'):
                    db.execute(query,row)
                if ordered:
                    qualified=schema(kind,prefix)+'.'+table
                    db.execute(sql.SQL('SELECT setval(pg_get_serial_sequence(%s,\'insertion_order\'), '
                        'COALESCE(MAX(insertion_order),1),MAX(insertion_order) IS NOT NULL) FROM {}').format(target),(qualified,))
                count=db.execute(sql.SQL('SELECT COUNT(*) FROM {}').format(target)).fetchone()[0]
                if count!=details['count']:raise RuntimeError('import row count mismatch')
        # PostgreSQL projections rely on seen receipts, never the imported cursor.
        db.execute(sql.SQL('INSERT INTO {} VALUES(%s,%s)').format(metadata),(key,json.dumps(manifest,sort_keys=True)))
        return {'replayed':False,'source_digest':key,'manifest':manifest}
    finally:
        for source in sources.values():source.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--import-sqlite',action='store_true')
    parser.add_argument('--writers-stopped',action='store_true')
    parser.add_argument('--grant',action='append',default=[],metavar='PROFILE=ROLE')
    args=parser.parse_args()
    import psycopg
    prefix=namespace()
    with psycopg.connect(database_url()) as db:
        initialize(db,prefix)
        result=import_sqlite(db,prefix,writers_stopped=args.writers_stopped) if args.import_sqlite else {'initialized':True}
        for grant in args.grant:
            profile,role=grant.split('=',1)
            grant_profile(db,prefix,role,profile)
    print(json.dumps({'namespace':prefix,**result},ensure_ascii=False))


if __name__=='__main__':main()
