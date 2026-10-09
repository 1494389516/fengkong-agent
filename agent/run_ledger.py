"""Transactional run/step ledger. Every worker write checks the live fencing token.

Only committed JSON results replay. An unfinished external request is ambiguous:
no provider-level exactly-once guarantee is claimed or silently retried.
"""
from .storage import postgres, begin_write, local_schema, table_names, order_column, json_text
from contextlib import contextmanager
import json
import sqlite3
import time
import uuid
from .evidence_snapshot import digest
from .resource_budget import ResourceBudgetExceeded

class LeaseLost(RuntimeError): pass
class AmbiguousExternalCall(RuntimeError): pass

class RunLedger:
    def __init__(self, db, task_id, token):
        self.db, self.task_id, self.token = db, task_id, token
        local_schema(db,'''
          CREATE TABLE IF NOT EXISTS run_steps(
            task_id TEXT, node_id TEXT, kind TEXT, input_digest TEXT,
            status TEXT, output TEXT, worker_token TEXT,
            PRIMARY KEY(task_id,node_id));
          CREATE TABLE IF NOT EXISTS run_contracts(
            task_id TEXT PRIMARY KEY, privacy_salt TEXT NOT NULL, created_at REAL);
          CREATE TABLE IF NOT EXISTS budget_contracts(task_id TEXT PRIMARY KEY, body TEXT);
          CREATE TABLE IF NOT EXISTS reservation_contracts(
            task_id TEXT, receipt_id TEXT, component TEXT, maximum INTEGER, ceiling INTEGER,
            PRIMARY KEY(task_id,receipt_id));
          CREATE TABLE IF NOT EXISTS resource_receipts(
            task_id TEXT, receipt_id TEXT, resource TEXT, amount INTEGER, worker_token TEXT,
            PRIMARY KEY(task_id,receipt_id,resource));
          CREATE TABLE IF NOT EXISTS budget_receipts(
            task_id TEXT, receipt_id TEXT, component TEXT, reserved INTEGER,
            actual_used INTEGER DEFAULT 0, estimated_used INTEGER DEFAULT 0,
            status TEXT, worker_token TEXT, PRIMARY KEY(task_id,receipt_id));
        ''')
        with self.transaction():
            db.execute('INSERT INTO run_contracts VALUES(?,?,?) ON CONFLICT DO NOTHING',
                       (task_id, uuid.uuid4().hex, time.time()))
        row=db.execute('SELECT body FROM budget_contracts WHERE task_id=?',(task_id,)).fetchone()
        self.budget_contract=json.loads(row[0]) if row else {}
        self.privacy_salt=db.execute('SELECT privacy_salt FROM run_contracts WHERE task_id=?',(task_id,)).fetchone()[0]

    @contextmanager
    def transaction(self):
        begin_write(self.db)
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

    def configure_budget(self, budget):
        """Pin the complete server-owned contract across worker replacement."""
        if 'pricing' in budget:
            from .investigation_pricing import validate
            validate(budget['pricing'])
        encoded=json.dumps(budget,sort_keys=True,allow_nan=False)
        for name,value in budget.items():
            if name.startswith('max_') and (type(value) is not int or value<=0):
                raise ValueError('positive integer budget required: '+name)
        with self.transaction():
            row=self.db.execute('SELECT body FROM budget_contracts WHERE task_id=?',(self.task_id,)).fetchone()
            if row and json.loads(row[0])!=budget:raise ValueError('budget contract changed; create a new run')
            if not row and self.db.execute('SELECT 1 FROM run_steps WHERE task_id=? LIMIT 1',(self.task_id,)).fetchone():
                raise AmbiguousExternalCall('legacy run lacks resource receipts; create a new run')
            self.db.execute('INSERT INTO budget_contracts VALUES(?,?) ON CONFLICT DO NOTHING',(self.task_id,encoded))
        self.budget_contract=json.loads(encoded)

    def _charge_resource(self, receipt, resource, amount):
        if type(amount) is not int or amount<0:raise ValueError('invalid resource amount')
        old=self.db.execute('SELECT amount FROM resource_receipts WHERE task_id=? AND receipt_id=? AND resource=?',
                            (self.task_id,receipt,resource)).fetchone()
        if old:
            if old[0]!=amount:raise ValueError('resource receipt changed')
            return
        limit=self.budget_contract.get('max_'+resource)
        if limit is None:raise ValueError('resource budget not configured: '+resource)
        used=self.db.execute('SELECT COALESCE(SUM(amount),0) FROM resource_receipts WHERE task_id=? AND resource=?',
                            (self.task_id,resource)).fetchone()[0]
        if used+amount>limit:raise ResourceBudgetExceeded('persistent investigation resource budget exhausted: '+resource)
        self.db.execute('INSERT INTO resource_receipts VALUES(?,?,?,?,?)',
                        (self.task_id,receipt,resource,amount,self.token))

    def charge_resource(self, receipt, resource, amount):
        with self.transaction():self._charge_resource(receipt,resource,amount)

    def resource_usage(self):
        return dict(self.db.execute('SELECT resource,SUM(amount) FROM resource_receipts WHERE task_id=? GROUP BY resource',
                                    (self.task_id,)))

    def cost_usage(self):
        pricing=self.budget_contract.get('pricing')
        if pricing is None:return {'status':'unpriced','currency':'USD'}
        rates=pricing['rates_nano_usd_per_token']
        totals={'reserved_nano_usd':0,'usage_bound_nano_usd':0,'estimated_bound_nano_usd':0}
        for component,reserved,actual,estimated in self.db.execute(
                'SELECT component,reserved,actual_used,estimated_used FROM budget_receipts WHERE task_id=?',(self.task_id,)):
            if component not in rates:raise ValueError('unpriced provider component')
            for field,amount in zip(totals,(reserved,actual,estimated)):totals[field]+=amount*rates[component]
        return dict(totals,status='operator_price_upper_bound',currency='USD',pricing_version=pricing['version'],
                    max_cost_nano_usd=pricing['max_cost_nano_usd'],invoice_verified=False)

    def _check_cost(self, component, maximum):
        pricing=self.budget_contract.get('pricing')
        if pricing is None:return
        rates=pricing['rates_nano_usd_per_token']
        if component not in rates:raise ValueError('unpriced provider component')
        usage=self.cost_usage()
        total=sum(usage[k] for k in ('reserved_nano_usd','usage_bound_nano_usd','estimated_bound_nano_usd'))
        if total+maximum*rates[component]>pricing['max_cost_nano_usd']:
            raise ResourceBudgetExceeded('persistent investigation cost budget exhausted')

    def reserve(self, receipt, component, maximum, limit):
        if type(maximum) is not int or maximum<=0 or type(limit) is not int or limit<=0: raise ValueError('invalid reservation')
        with self.transaction():
            pinned=self.budget_contract.get('max_tokens',limit)
            if limit!=pinned:raise ValueError('token budget contract changed')
            contract=self.db.execute('SELECT component,maximum,ceiling FROM reservation_contracts WHERE task_id=? AND receipt_id=?',
                                     (self.task_id,receipt)).fetchone()
            if contract and contract!=(component,maximum,limit):raise ValueError('reservation contract changed')
            self.db.execute('INSERT INTO reservation_contracts VALUES(?,?,?,?,?) ON CONFLICT DO NOTHING',
                            (self.task_id,receipt,component,maximum,limit))
            row=self.db.execute('SELECT status FROM budget_receipts WHERE task_id=? AND receipt_id=?',
                                (self.task_id,receipt)).fetchone()
            if row: return
            self._check_cost(component,maximum)
            used=self.db.execute('SELECT COALESCE(SUM(reserved+actual_used+estimated_used),0) FROM budget_receipts WHERE task_id=?',
                                 (self.task_id,)).fetchone()[0]
            if used+maximum>limit: raise ResourceBudgetExceeded('persistent investigation budget exhausted')
            self.db.execute('INSERT INTO budget_receipts(task_id,receipt_id,component,reserved,status,worker_token) VALUES(?,?,?,?,?,?)',
                            (self.task_id,receipt,component,maximum,'reserved',self.token))

    def settle(self, receipt, actual=None):
        with self.transaction():
            self._settle(receipt,actual)

    def _settle(self, receipt, actual):
        row=self.db.execute('SELECT reserved,status,actual_used,estimated_used FROM budget_receipts WHERE task_id=? AND receipt_id=?',
                            (self.task_id,receipt)).fetchone()
        if not row: raise ValueError('unknown reservation')
        if actual is not None and (type(actual) is not int or actual<0): raise ValueError('invalid provider usage')
        if row[1]=='settled':
            if (actual is None and row[3]==0) or (actual is not None and (row[2]!=actual or row[3]!=0)):
                raise ValueError('settlement changed')
            return
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
            if kind!='read_tool' and 'max_provider_input_bytes' in self.budget_contract:
                from .resource_budget import json_bytes
                self._charge_resource(node,'provider_input_bytes',json_bytes(inputs))
            resource='tool_calls' if kind=='read_tool' else 'provider_calls'
            if 'max_'+resource in self.budget_contract:
                # Charge every attempted read, including an uncertain read retry.
                # Completed-step replay returned above and is free.
                attempt=node+':'+uuid.uuid4().hex
                self._charge_resource(attempt,resource,1)
                if kind=='read_tool' and (inputs.get('name') or inputs.get('tool'))=='search_risk_knowledge':
                    if 'max_knowledge_searches' in self.budget_contract:
                        self._charge_resource(attempt,'knowledge_searches',1)
        return None

    def complete(self, node, output, *, receipt=None, actual=None):
        encoded=json.dumps(output,ensure_ascii=False,allow_nan=False)
        with self.transaction():
            kind=self.db.execute('SELECT kind FROM run_steps WHERE task_id=? AND node_id=?',(self.task_id,node)).fetchone()
            if kind and kind[0]!='read_tool' and 'max_provider_output_bytes' in self.budget_contract:
                self._charge_resource(node,'provider_output_bytes',len(encoded.encode()))
            changed=self.db.execute("UPDATE run_steps SET status='completed',output=? WHERE task_id=? AND node_id=? AND worker_token=? AND status='started'",
                                    (encoded,self.task_id,node,self.token)).rowcount
            if changed!=1: raise LeaseLost('step ownership lost')
            if receipt: self._settle(receipt,actual)

    def commit_result(self, result):
        begin_write(self.db)
        try:
            self.assert_live()
            self.db.execute("UPDATE investigation_tasks SET status='success',result=?,lease_until=0 WHERE task_id=? AND lease_token=?",
                            (json.dumps(result,allow_nan=False),self.task_id,self.token))
            self.db.execute("UPDATE investigation_runs SET status='completed' WHERE task_id=? AND worker_token=?",(self.task_id,self.token))
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
    try:
        payload, actual = invoke()
    except Exception as exc:
        raise AmbiguousExternalCall('provider response unavailable after request start: '+component) from exc
    ledger.complete(node, {'payload':payload}, receipt=node, actual=actual)
    usage=ledger.usage()
    ledger._check_cost(component,0)
    if sum(usage.values())>ledger.max_tokens:
        raise ResourceBudgetExceeded('persistent investigation budget exceeded after provider response')
    return payload


def propagate_runtime_failure(exc):
    """Provider fallback cannot erase fencing, ambiguity or budget exhaustion."""
    if _current.get() is not None and isinstance(exc,(LeaseLost,AmbiguousExternalCall,ResourceBudgetExceeded)):
        raise exc
