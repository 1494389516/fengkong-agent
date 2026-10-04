"""SQLite run/step ledger. Every worker write checks the live fencing token.

Only committed JSON results replay. An unfinished external request is ambiguous:
no provider-level exactly-once guarantee is claimed or silently retried.
"""
from contextlib import contextmanager
import json
import sqlite3
import time
import uuid
from .evidence_snapshot import digest

class LeaseLost(RuntimeError): pass
class AmbiguousExternalCall(RuntimeError): pass

class RunLedger:
    def __init__(self, db, task_id, token):
        self.db, self.task_id, self.token = db, task_id, token
        db.executescript('''
          CREATE TABLE IF NOT EXISTS run_steps(
            task_id TEXT, node_id TEXT, kind TEXT, input_digest TEXT,
            status TEXT, output TEXT, worker_token TEXT,
            PRIMARY KEY(task_id,node_id));
          CREATE TABLE IF NOT EXISTS run_contracts(
            task_id TEXT PRIMARY KEY, privacy_salt TEXT NOT NULL, created_at REAL);
          CREATE TABLE IF NOT EXISTS budget_receipts(
            task_id TEXT, receipt_id TEXT, component TEXT, reserved INTEGER,
            actual_used INTEGER DEFAULT 0, estimated_used INTEGER DEFAULT 0,
            status TEXT, worker_token TEXT, PRIMARY KEY(task_id,receipt_id));
        ''')
        with self.transaction():
            db.execute('INSERT OR IGNORE INTO run_contracts VALUES(?,?,?)',
                       (task_id, uuid.uuid4().hex, time.time()))
        self.privacy_salt=db.execute('SELECT privacy_salt FROM run_contracts WHERE task_id=?',(task_id,)).fetchone()[0]

    @contextmanager
    def transaction(self):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self.assert_live()
            yield
            self.assert_live()
            self.db.commit()
        except BaseException:
            self.db.rollback();raise

    def assert_live(self):
        row=self.db.execute('SELECT status,lease_token,lease_until FROM investigation_tasks WHERE task_id=?',
                            (self.task_id,)).fetchone()
        if not row or row[0]!='running' or row[1]!=self.token or row[2]<=time.time():
            raise LeaseLost('worker fencing token expired or replaced')

    def reserve(self, receipt, component, maximum, limit):
        if type(maximum) is not int or maximum<=0: raise ValueError('invalid reservation')
        with self.transaction():
            row=self.db.execute('SELECT status FROM budget_receipts WHERE task_id=? AND receipt_id=?',
                                (self.task_id,receipt)).fetchone()
            if row: return
            used=self.db.execute('SELECT COALESCE(SUM(reserved+actual_used+estimated_used),0) FROM budget_receipts WHERE task_id=?',
                                 (self.task_id,)).fetchone()[0]
            if used+maximum>limit: raise PermissionError('persistent investigation budget exhausted')
            self.db.execute('INSERT INTO budget_receipts(task_id,receipt_id,component,reserved,status,worker_token) VALUES(?,?,?,?,?,?)',
                            (self.task_id,receipt,component,maximum,'reserved',self.token))

    def settle(self, receipt, actual=None):
        with self.transaction():
            self._settle(receipt,actual)

    def _settle(self, receipt, actual):
        row=self.db.execute('SELECT reserved,status FROM budget_receipts WHERE task_id=? AND receipt_id=?',
                            (self.task_id,receipt)).fetchone()
        if not row: raise ValueError('unknown reservation')
        if row[1]=='settled': return
        if actual is not None and (type(actual) is not int or actual<0): raise ValueError('invalid provider usage')
        self.db.execute('UPDATE budget_receipts SET reserved=0,actual_used=?,estimated_used=?,status=?,worker_token=? '
                        'WHERE task_id=? AND receipt_id=?',
                        (actual or 0, row[0] if actual is None else 0,'settled',self.token,self.task_id,receipt))

    def usage(self):
        row=self.db.execute('SELECT COALESCE(SUM(reserved),0),COALESCE(SUM(actual_used),0),COALESCE(SUM(estimated_used),0) '
                            'FROM budget_receipts WHERE task_id=?',(self.task_id,)).fetchone()
        return dict(zip(('reserved','actual_used','estimated_used'),row))

    def begin(self, node, kind, inputs):
        fingerprint=digest(inputs)
        with self.transaction():
            row=self.db.execute('SELECT kind,input_digest,status,output FROM run_steps WHERE task_id=? AND node_id=?',
                                (self.task_id,node)).fetchone()
            if row:
                if row[:2]!=(kind,fingerprint): raise ValueError('step input or workflow version changed; create a new run')
                if row[2]=='completed': return json.loads(row[3])
                if kind!='read_tool': raise AmbiguousExternalCall('ambiguous_external_call: '+node)
                self.db.execute('UPDATE run_steps SET worker_token=? WHERE task_id=? AND node_id=?',
                                (self.token,self.task_id,node))
            else:
                self.db.execute('INSERT INTO run_steps VALUES(?,?,?,?,?,?,?)',
                    (self.task_id,node,kind,fingerprint,'started',None,self.token))
        return None

    def complete(self, node, output, *, receipt=None, actual=None):
        encoded=json.dumps(output,ensure_ascii=False,allow_nan=False)
        with self.transaction():
            changed=self.db.execute("UPDATE run_steps SET status='completed',output=? WHERE task_id=? AND node_id=? AND worker_token=? AND status='started'",
                                    (encoded,self.task_id,node,self.token)).rowcount
            if changed!=1: raise LeaseLost('step ownership lost')
            if receipt: self._settle(receipt,actual)

    def commit_result(self, result):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self.assert_live()
            self.db.execute("UPDATE investigation_tasks SET status='success',result=?,lease_until=0 WHERE task_id=? AND lease_token=?",
                            (json.dumps(result,allow_nan=False),self.task_id,self.token))
            self.db.commit()
        except BaseException:
            self.db.rollback();raise


from contextvars import ContextVar
_current = ContextVar('run_budget_ledger', default=None)


def metered_call(component, inputs, maximum, invoke):
    """invoke returns JSON-safe payload and complete usage, or None for unknown."""
    ledger = _current.get()
    if ledger is None:
        return invoke()[0]
    node = component + ':' + digest(inputs)
    ledger.reserve(node, component, maximum, ledger.max_tokens)
    cached = ledger.begin(node, component, inputs)
    if cached is not None:
        return cached['payload']
    payload, actual = invoke()
    ledger.complete(node, {'payload':payload}, receipt=node, actual=actual)
    return payload
