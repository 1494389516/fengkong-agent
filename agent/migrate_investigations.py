"""Explicit one-time copy of legacy investigation records; never deletes source."""
import sqlite3
from .tools.datasource import data_dir
from .investigations import _db


def migrate():
    source=data_dir()/'online.sqlite3'
    db=_db(_migration=True)
    source_db=sqlite3.connect(source.as_uri()+'?mode=ro',uri=True)
    try:
        source_db.execute('BEGIN')
        tables={r[0] for r in source_db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        db.execute('BEGIN IMMEDIATE')
        counts={}
        for table,key in (('cases','case_id'),('investigation_tasks','task_id'),('investigation_seen','decision_id')):
            if table not in tables:counts[table]=0;continue
            names=[r[1] for r in source_db.execute('PRAGMA table_info('+table+')')]
            expected={'cases':{'case_id','tenant','app','entity','bucket','body'},
                      'investigation_tasks':{'task_id','case_id','snapshot','status','result','lease_until','lease_token'},
                      'investigation_seen':{'decision_id'}}[table]
            if set(names)!=expected:raise ValueError('unsupported legacy schema: '+table)
            rows=source_db.execute('SELECT '+','.join(names)+' FROM '+table).fetchall()
            for row in rows:
                old=db.execute('SELECT '+','.join(names)+' FROM '+table+' WHERE '+key+'=?',(row[names.index(key)],)).fetchone()
                if old is not None:
                    if old!=row:raise ValueError('migration conflicts with existing '+table)
                    continue
                db.execute('INSERT INTO '+table+'('+','.join(names)+') VALUES('+','.join('?' for _ in names)+')',row)
            counts[table]=len(rows)
        db.execute("INSERT OR REPLACE INTO agent_store_meta VALUES('legacy_migrated','1')")
        db.commit();return counts
    except BaseException:
        db.rollback();raise
    finally:source_db.close();db.close()


def main():
    import json,os
    from .tenancy import authenticate,data_context
    ctx=authenticate('Bearer '+os.environ.get('FK_PROJECTOR_TOKEN',''))
    ctx.require('cases.project')
    with data_context(ctx):print(json.dumps(migrate()))
if __name__=='__main__':main()
