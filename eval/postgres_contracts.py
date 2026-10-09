"""Real PostgreSQL contracts: transactions, commit inversion, leases and role boundaries."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch

if os.environ.get('FK_REQUIRE_POSTGRES_TESTS') and not os.environ.get('FK_DATABASE_URL'):
    raise RuntimeError('PostgreSQL CI must provide its service URL')


@unittest.skipUnless(os.environ.get('FK_DATABASE_URL'), 'requires real PostgreSQL')
class PostgresContracts(unittest.TestCase):
    def setUp(self):
        import psycopg
        from agent.tenancy import AuthContext, data_context
        from agent.storage import namespace, KINDS, schema
        from agent.storage.migrate import initialize
        self.root=Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.tenant='t'+uuid.uuid4().hex
        record=dict(principal='worker',tenant=self.tenant,app='a',data_dir=str(self.root),
                    source_kind='business',permissions=['cases.run','cases.read','cases.review','decisions.write'],expires_at=time.time()+600)
        auth=self.root/'auth.json';auth.write_text(json.dumps({hashlib.sha256(b'test').hexdigest():record}))
        self.enterContext(patch.dict(os.environ,{'FK_STORAGE_BACKEND':'postgres','FK_DATA_DIR':str(self.root),
            'FK_AUTH_CONFIG':str(auth),'FK_ENV':'development','FK_GRAPH_ALGORITHM':'community_v1',
            'FK_GRAPH_SHADOW_ALGORITHM':'','FK_GRAPH_REFRESH_POLICY':'strict'}))
        self.ctx=AuthContext('worker',self.tenant,'a',str(self.root),'business',tuple(record['permissions']),record['expires_at'])
        self.enterContext(data_context(self.ctx));self.prefix=namespace()
        self.url=os.environ['FK_DATABASE_URL']
        with psycopg.connect(self.url) as db:initialize(db,self.prefix)
        def cleanup():
            from psycopg import sql
            with psycopg.connect(self.url) as db:
                for kind in KINDS:db.execute(sql.SQL('DROP SCHEMA {} CASCADE').format(sql.Identifier(schema(kind,self.prefix))))
        self.addCleanup(cleanup)

    def threaded(self, function, count=4):
        from agent.tenancy import data_context
        def call(i):
            with data_context(self.ctx):return function(i)
        with ThreadPoolExecutor(max_workers=count) as pool:return list(pool.map(call,range(count)))

    def record(self, ident, action='pass'):
        return dict(action=action,tenant_id=self.tenant,app_id='a',decision_id=ident,
            evaluated_at=time.time(),event={'uid':'u','event_id':ident,'ts':time.time()-1,'device_id':'d'},business_event_id=ident)

    def test_decision_atomicity_idempotency_and_account_query(self):
        from agent.tools.online_store import decide, connect
        from agent.tools.datasource import selected_account_events
        event={'event_id':'e','uid':'u','ts':time.time()}
        def compute(e,operator):
            self.assertEqual(selected_account_events('u',e['ts'],300),[])
            return {'action':'review'}
        def invoke(i):return decide(event,'worker',compute,scope=(self.tenant,'a'),source_kind='business',received_at=None)
        results=self.threaded(invoke)
        self.assertEqual(sum(not replay for _,replay in results),1)
        self.assertEqual(len({r['decision_id'] for r,_ in results}),1)
        with patch('agent.tools.online_store._fault',side_effect=RuntimeError('rollback')):
            with self.assertRaises(RuntimeError):decide(dict(event,event_id='bad'),'worker',lambda *_:{'action':'pass'},scope=(self.tenant,'a'),source_kind='business',received_at=None)
        with closing(connect()) as db:
            for table in ('decisions','events','outbox'):
                self.assertEqual(db.execute('SELECT COUNT(*) FROM '+table).fetchone()[0],1)

    def test_late_commit_is_not_skipped_and_projectors_deduplicate(self):
        from agent.tools.online_store import connect
        from agent.investigations import consume_decision_outbox, _db
        a=connect();b=connect()
        try:
            a.execute('INSERT INTO outbox(decision_id,body) VALUES(?,?)',('first',json.dumps(self.record('first'))))
            b.execute('INSERT INTO outbox(decision_id,body) VALUES(?,?)',('second',json.dumps(self.record('second'))));b.commit()
            self.assertEqual(consume_decision_outbox(),1)
            a.commit()
            self.assertEqual(sum(self.threaded(lambda _:consume_decision_outbox())),1)
            with closing(_db()) as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM investigation_seen').fetchone()[0],2)
        finally:a.close();b.close()

    def test_group_claims_renewal_and_expired_fencing(self):
        from agent.event_bus import event_bus
        bus=event_bus('graph')
        for n in range(12):bus.publish('topic',str(n),{'n':n})
        batches=self.threaded(lambda _:bus.claim('topic',limit=3))
        events=[e for batch in batches for e in batch]
        self.assertEqual(len(events),12);self.assertEqual(len({e.event_id for e in events}),12)
        self.assertTrue(bus.renew(events[0].event_id,events[0].lease_token))
        self.assertTrue(bus.acknowledge(events[0].event_id,events[0].lease_token))
        self.assertFalse(bus.acknowledge(events[0].event_id,events[0].lease_token))
        self.assertEqual(len(event_bus('other').claim('topic',limit=12)),12)
        self.assertTrue(bus.fail(events[1].event_id,events[1].lease_token,'retry'))

    def test_projection_snapshot_and_immutable_history(self):
        import psycopg
        from agent.tools.online_store import connect
        from agent.investigations import consume_decision_outbox, _db
        with closing(connect()) as db:
            r=self.record('review','review')
            db.execute('INSERT INTO outbox(decision_id,body) VALUES(?,?)',('review',json.dumps(r)))
            db.execute('INSERT INTO events VALUES(?,?,?,?,?,?)',(self.tenant,'a','history',r['event']['ts']-1,r['event']['ts']-1,json.dumps(r['event'])))
            db.commit()
        self.assertEqual(consume_decision_outbox(),1)
        with closing(_db()) as db:
            snapshot=json.loads(db.execute('SELECT snapshot FROM investigation_tasks').fetchone()[0])
            self.assertEqual(len(snapshot['events']),1)
            with self.assertRaises(psycopg.Error):db.execute("UPDATE case_revisions SET body='{}'")
            db.rollback()

    def test_ledger_replay_and_budget_fence(self):
        from agent.investigations import _db
        from agent.run_ledger import RunLedger, LeaseLost, AmbiguousExternalCall
        with closing(_db()) as db:
            db.execute("INSERT INTO investigation_tasks(task_id,status,lease_token,lease_until) VALUES('task','running','A',?)",(time.time()+60,));db.commit()
            ledger=RunLedger(db,'task','A');ledger.configure_budget({'max_tokens':1000,'max_tool_calls':2})
            ledger.reserve('one','generator',800,1000);ledger.begin('one','llm',{})
            ledger.complete('one',{'answer':'ok'},receipt='one',actual=100)
            self.assertEqual(ledger.begin('one','llm',{}),{'answer':'ok'})
            ledger.begin('ambiguous','llm',{})
            db.execute("UPDATE investigation_tasks SET lease_token='B'");db.commit()
            with self.assertRaises(LeaseLost):ledger.complete('ambiguous',{})
            other=RunLedger(db,'task','B')
            with self.assertRaises(AmbiguousExternalCall):other.begin('ambiguous','llm',{})
            self.assertEqual(other.usage()['actual_used'],100)

    def test_graph_refresh_previous_revision_and_fencing(self):
        from agent import graph_risk
        from agent.graph_store import graph_store
        from agent.online_feature_store import online_feature_store
        from agent.storage import connect, projection_lock
        now=time.time()
        observation=dict(evidence_id='one',tenant_id=self.tenant,app_id='a',uid='u',device_id='d',
            entity_generation='g',identity_trust='server_bound',observed_at=now,recorded_at=now)
        graph_risk.ingest_observation(observation)
        old=graph_risk.lookup(self.tenant,'a','d','g')
        self.assertIsNotNone(old)
        with patch.dict(os.environ,{'FK_GRAPH_REFRESH_POLICY':'bounded_previous'}):
            with patch('agent.graph_risk.graph_algorithm',side_effect=RuntimeError('compute failed')):
                with self.assertRaises(RuntimeError):graph_risk.ingest_observation(dict(observation,evidence_id='two'))
            previous=graph_risk.lookup(self.tenant,'a','d','g')
            self.assertEqual(previous['feature_revision'],old['feature_revision'])
            self.assertEqual(previous['feature_refresh_status'],'refreshing')
        self.assertIsNone(graph_risk.lookup(self.tenant,'a','d','g'))
        self.assertEqual(graph_risk.refresh_dirty_devices()['refreshed'],1)
        with projection_lock():
            with closing(connect('graph')) as replacement:
                replacement.execute('UPDATE projection_epoch SET epoch=epoch+1');replacement.commit()
            with self.assertRaisesRegex(RuntimeError,'fencing'):
                online_feature_store().put(self.tenant,'a','device','d','g','graph_risk_v1',{'algorithm':'community_v1'})
            with self.assertRaisesRegex(RuntimeError,'fencing'):graph_store().clear_dirty(self.tenant,'a','d','g')

    def test_transactional_sqlite_import_bytes_and_replay(self):
        import psycopg
        from agent.storage.migrate import import_sqlite
        with patch.dict(os.environ,{'FK_STORAGE_BACKEND':'sqlite'}):
            from agent.collector import _database
            with closing(_database()) as db:
                db.execute('INSERT INTO evidence VALUES(?,?,?,?,?,?,?,?)',('id',self.tenant,'a',b'\x00\xff',b'{}','digest',time.time(),'{}'));db.commit()
        with psycopg.connect(self.url) as db:
            first=import_sqlite(db,self.prefix,writers_stopped=True)
        self.assertFalse(first['replayed'])
        with psycopg.connect(self.url) as db:self.assertTrue(import_sqlite(db,self.prefix,writers_stopped=True)['replayed'])
        from agent.storage import connect
        with closing(connect('online')) as db:
            self.assertEqual(db.execute('SELECT raw_envelope FROM evidence').fetchone()[0],b'\x00\xff')

    def test_database_role_cannot_mutate_evidence_or_other_tenant(self):
        import psycopg
        from psycopg import sql
        from agent.storage.migrate import grant_profile, initialize
        from agent.storage import schema
        role='fk_eval_'+uuid.uuid4().hex[:12]
        other='fk_'+uuid.uuid4().hex
        admin=psycopg.connect(self.url,autocommit=True)
        try:
            admin.execute(sql.SQL('CREATE ROLE {}').format(sql.Identifier(role)))
            with admin.transaction():initialize(admin,other);grant_profile(admin,self.prefix,role,'agent')
            admin.execute(sql.SQL('SET ROLE {}').format(sql.Identifier(role)))
            admin.execute(sql.SQL('SELECT * FROM {}.evidence').format(sql.Identifier(schema('online',self.prefix))))
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                admin.execute(sql.SQL('DELETE FROM {}.evidence').format(sql.Identifier(schema('online',self.prefix))))
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                admin.execute(sql.SQL('SELECT * FROM {}.evidence').format(sql.Identifier(schema('online',other))))
        finally:
            admin.execute('RESET ROLE')
            for kind in ('online','agent','graph','features','knowledge'):
                admin.execute(sql.SQL('DROP SCHEMA IF EXISTS {} CASCADE').format(sql.Identifier(schema(kind,other))))
            admin.execute(sql.SQL('DROP OWNED BY {}').format(sql.Identifier(role)))
            admin.execute(sql.SQL('DROP ROLE {}').format(sql.Identifier(role)));admin.close()

    def test_signed_collector_evidence_and_bus_rollback_together(self):
        import base64
        from dataclasses import replace
        from agent.collector import ingest
        from agent.contracts.report_contract import legacy_mac, signature_input
        from agent.storage import connect
        now=time.time();payload=b'{"sg":[]}'
        (self.root/'keys.json').write_text(json.dumps({'key':base64.b64encode(b'k'*32).decode()}))
        (self.root/'identity').write_bytes(b'i'*32)
        attrs=dict(subject='installation',generation='g',account_id='u',key_ids=['key'],
                   session_sha256=hashlib.sha256(b'session').hexdigest())
        ctx=replace(self.ctx,source_kind='sdk',permissions=('reports.write','cases.read'),attributes=attrs)
        def upload(ident):
            nonce='n'+ident;ts=int(now*1000)
            prefix=f'{len(nonce)}:{nonce}|{ts}|{len(ident)}:{ident}|'.encode()
            value=dict(kind='sdk_report',contract_version=1,app_id='a',sdk_version='6.5.0',
                report_id=ident,ts=ts,nonce=nonce,session_token='session',sig_ver='v3',key_id='key',
                device_id='installation',scene='login',field_mapping_version='',
                payload_json=base64.b64encode(payload).decode(),
                payload_sha256=base64.b64encode(hashlib.sha256(prefix+payload).digest()).decode())
            value['signature']=legacy_mac(b'k'*32,signature_input(value));return value
        with patch.dict(os.environ,{'FK_COLLECTOR_KEYS':str(self.root/'keys.json'),'FK_IDENTITY_KEY_FILE':str(self.root/'identity')}):
            with patch('agent.event_bus.LocalEventBus.publish',side_effect=RuntimeError('bus failure')):
                with self.assertRaises(RuntimeError):ingest(upload('failed'),ctx,now=now)
            value=upload('accepted');receipt=ingest(value,ctx,now=now)
            self.assertTrue(ingest(value,ctx,now=now)['idempotent_replay'])
        with closing(connect('online')) as db:
            for table in ('evidence','report_receipts','integration_events'):
                self.assertEqual(db.execute('SELECT COUNT(*) FROM '+table).fetchone()[0],1)
            self.assertEqual(db.execute('SELECT raw_payload FROM evidence WHERE evidence_id=?',(receipt['evidence_id'],)).fetchone()[0],payload)

    def test_full_investigation_and_independent_review(self):
        from dataclasses import replace
        from agent.tools.online_store import connect
        from agent.investigations import consume_decision_outbox, run_task, _db
        from agent.case_review import review
        from agent.evidence_snapshot import digest
        with closing(connect()) as db:
            db.execute('INSERT INTO outbox(decision_id,body) VALUES(?,?)',('case',json.dumps(self.record('case','review'))));db.commit()
        consume_decision_outbox()
        with closing(_db()) as db:task=db.execute('SELECT task_id FROM investigation_tasks').fetchone()[0]
        class FixtureAgent:
            def ask(self,prompt,scope=None):
                return json.dumps(dict(verdict='evidence_gap',claims=[],missing_evidence=['fixture only'],recommended_next_step='human review'))
        ctx=replace(self.ctx,attributes={'tools':['get_event_evidence']})
        result=run_task(task,ctx,agent_factory=FixtureAgent)
        self.assertEqual(result['status'],'success')
        self.assertEqual(run_task(task,ctx,agent_factory=FixtureAgent),result)
        request=dict(task_id=task,result_digest=digest(result),verdict='insufficient',note='synthetic fixture',matures_at=time.time(),request_id='one')
        with self.assertRaises(PermissionError):review(ctx,request)
        reviewer=replace(ctx,principal='independent-reviewer')
        self.assertEqual(review(reviewer,request),review(reviewer,request))

    def test_sql_timeout_keeps_outer_transaction_usable(self):
        from agent.storage import connect, begin_write
        from agent.compute_budget import feature_budget,sql_budget,ComputeBudgetExceeded
        from agent.compute_admission import DEFAULT_CONTRACT
        with closing(connect('online')) as db:
            begin_write(db)
            with self.assertRaises(ComputeBudgetExceeded):
                with feature_budget(dict(DEFAULT_CONTRACT,deadline_ms=1)),sql_budget(db):
                    db.execute('SELECT pg_sleep(0.05)')
            db.execute('INSERT INTO outbox(decision_id,body) VALUES(?,?)',('fallback',json.dumps(self.record('fallback'))));db.commit()
        with closing(connect('online')) as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM outbox').fetchone()[0],1)

    def test_readonly_knowledge_index(self):
        from agent.storage import connect
        from agent.rag.store import index_metadata, read_index
        with closing(connect('knowledge')) as db:
            db.execute('INSERT INTO metadata VALUES(?,?)',('index_digest','fixture'))
            db.execute('INSERT INTO chunks VALUES(?,?)',('chunk',json.dumps({'chunk_id':'chunk','text':'fixture'})));db.commit()
        self.assertEqual(index_metadata()['index_digest'],'fixture')
        self.assertEqual(read_index()[1][0]['chunk_id'],'chunk')


if __name__=='__main__':unittest.main()
