import os
import tempfile
import unittest
from unittest.mock import patch
from agent import engine

class RuntimeCompletion(unittest.TestCase):
    def test_unbound_model_cannot_claim_champion_version(self):
        result = {'action':'pass', 'hits':[]}
        with patch.object(engine, '_model_score_local', return_value=.7):
            out = engine._apply_model_signal(result, {'uid':'u'}, champion_snapshot={'name':'m','version':'1'})
        self.assertNotIn('model_version', out)
        self.assertEqual(out['components']['model']['status'], 'invalid')
        self.assertEqual(out['expected_model_version'], 'm 1')

    def test_snapshot_is_deeply_isolated(self):
        from agent.runtime_bundle import request_bundle, current_bundle
        manifest = {'bundle':{'policy':{'threshold':10}}, 'activation':{'id':'a'}}
        with patch('agent.runtime_bundle._load', return_value=(manifest,None)):
            with request_bundle():
                first = current_bundle()
                first['policy']['threshold'] = 99
                self.assertEqual(current_bundle()['policy']['threshold'],10)
                with request_bundle():
                    self.assertEqual(current_bundle()['policy']['threshold'],10)

    def test_disk_registry_last_good_survives_memory_reset(self):
        from pathlib import Path
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)/'models.json'
            rows = [{'name':'m','version':'v','status':'champion'}]
            engine._read_registry(lambda:rows,p,'model')
            engine._registry_snapshots.clear()
            def bad(): raise ValueError('broken')
            recovered, error = engine._read_registry(bad,p,'model')
            self.assertEqual(recovered,rows)
            self.assertTrue(error['using_last_known_good'])

    def test_signed_activation_pinned_and_lkg_revalidated_after_restart(self):
        import base64, hashlib, json
        from pathlib import Path
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        from agent.release_publisher import canonical
        from agent.control_plane import digest
        from agent.runtime_bundle import request_bundle,current_bundle,annotate_bundle
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); (root/'bundles').mkdir(); key=Ed25519PrivateKey.generate()
            (root/'pub').write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
            def write(identifier,n):
                bundle={'policy':{'threshold':n},'versions':{'policy':str(n)},'strategy':{},'model':{},'feature':{},'list':{'records':[]},'graph':{}}
                manifest={'bundle':bundle,'activation':{'id':identifier,'bundle_digest':digest(bundle)}}
                def signed(p):return canonical({'payload':p,'signature':base64.b64encode(key.sign(canonical(p))).decode()})
                raw=signed(manifest); (root/'bundles'/(identifier+'.json')).write_bytes(raw)
                (root/'active.json').write_bytes(signed({'activation_id':identifier,'manifest_sha256':hashlib.sha256(raw).hexdigest()}))
            write('a'*32,1)
            with patch.dict(os.environ,{'FK_RUNTIME_BUNDLE_DIR':td,'FK_RUNTIME_PUBLIC_KEY':str(root/'pub'),'FK_DATA_DIR':td}):
                with request_bundle():
                    write('b'*32,2)
                    self.assertEqual(current_bundle()['policy']['threshold'],1)
                with request_bundle():self.assertEqual(current_bundle()['policy']['threshold'],2)
                (root/'active.json').write_text('corrupt')
                with request_bundle():
                    self.assertEqual(current_bundle()['policy']['threshold'],2)
                    out=annotate_bundle({})
                    self.assertTrue(out['degraded'])
                    self.assertTrue(out['components']['runtime_bundle']['using_last_known_good'])
                (root/'bundles'/('b'*32+'.json')).write_text('corrupt')
                with self.assertRaisesRegex(RuntimeError,'no_verified'):
                    with request_bundle():pass

    def test_bound_model_provenance_must_match(self):
        for version,status in [('m 1','ok'),('m 2','invalid')]:
            with patch.object(engine,'_bound_model_score',return_value=(.1,version)):
                out=engine._apply_model_signal({'action':'pass','hits':[]},{'uid':'u'},champion_snapshot={'name':'m','version':'1'})
            self.assertEqual(out['components']['model']['status'],status)
            self.assertEqual('model_version' in out,status=='ok')

    def test_server_recorded_time_overwrites_client_and_crash_recovery(self):
        import subprocess,sys,json
        from agent.tools import online_store
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ,{'FK_DATA_DIR':td}):
            event={'event_id':'e','uid':'u','type':'order','ts':100,'recorded_at':1}
            row,_=online_store.decide(event,'op',lambda e,o:{'action':'pass'},scope=('t','a'),source_kind='business',received_at=300)
            self.assertEqual(row['event']['recorded_at'],300)
            for stage,expected in [('before_commit',0),('after_commit',1)]:
                with tempfile.TemporaryDirectory() as crashdir:
                    script="""import os
from agent.tools import online_store as s
s._fault=lambda stage:os._exit(71) if stage==os.environ['CRASH_STAGE'] else None
s.decide({'event_id':'crash','uid':'u','type':'order','ts':100},'op',lambda e,o:{'action':'pass'},scope=('t','a'),source_kind='business',received_at=300)
"""
                    env={**os.environ,'FK_DATA_DIR':crashdir,'CRASH_STAGE':stage}
                    self.assertEqual(subprocess.run([sys.executable,'-c',script],env=env).returncode,71)
                    with patch.dict(os.environ,{'FK_DATA_DIR':crashdir}):
                        db=online_store.connect()
                        self.assertEqual([db.execute('SELECT COUNT(*) FROM '+t).fetchone()[0] for t in ['decisions','events','outbox']],[expected]*3)
                        db.close()
                        _,replay=online_store.decide({'event_id':'crash','uid':'u','type':'order','ts':100},'op',lambda e,o:{'action':'pass'},scope=('t','a'),source_kind='business',received_at=301)
                        self.assertEqual(replay,bool(expected))

    def test_explicit_legacy_migration_replays_without_recompute(self):
        import json,subprocess,sys
        from pathlib import Path
        from agent.tools import online_store,idemp_store
        with tempfile.TemporaryDirectory() as td,patch.dict(os.environ,{'FK_DATA_DIR':td}):
            event={'event_id':'legacy','uid':'u','type':'order','ts':100}
            key=idemp_store.event_key('legacy')
            idemp_store.complete(key,{'action':'review'},'old-fp')
            mapping=Path(td)/'mapping.json'
            mapping.write_text(json.dumps({key:{'event':event,'source_kind':'business'}}))
            result=subprocess.run([sys.executable,'-m','agent.tools.online_store','migrate-legacy','--tenant','t','--app','a','--mapping',str(mapping)],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            row,replay=online_store.decide(event,'op',lambda e,o:self.fail('recomputed'),scope=('t','a'),source_kind='business',received_at=300)
            self.assertTrue(replay);self.assertEqual(row['action'],'review')


    def test_runtime_rejects_cross_tenant_or_app_scope(self):
        from agent.tenancy import AuthContext
        from agent.runtime_bundle import _check_scope
        import time
        ctx=AuthContext('p','t','a','/tmp','business',(),time.time()+60)
        with patch('agent.tenancy.current_context',return_value=ctx):
            _check_scope({'activation':{'scope':'tenant:t/app:a'}})
            for wrong in ['tenant:other/app:a','tenant:t/app:other','tenant:t',None]:
                with self.assertRaises(PermissionError):
                    _check_scope({'activation':{'scope':wrong}})

    def test_expired_report_replays_committed_request_only(self):
        import time
        from test_completion_http import CompletionHTTP
        server=CompletionHTTP()
        server.setUp()
        try:
            code,_=server.request('POST','/reports','a-sdk',server.fixture.upload())
            self.assertEqual(code,200)
            event={'event_id':'fresh-report-decision','uid':'u','type':'login','ts':time.time(),'report_ids':['r']}
            code,first=server.request('POST','/decide','a-business',event)
            self.assertEqual(code,200,first)
            import sqlite3,json
            db=sqlite3.connect(server.fixture.root/'a'/'online.sqlite3')
            saved=db.execute('SELECT evidence_id,observation FROM evidence').fetchone()
            obs=json.loads(saved[1]);obs['recorded_at']-=301
            db.execute('UPDATE evidence SET observation=? WHERE evidence_id=?',(json.dumps(obs),saved[0]));db.commit();db.close()
            code,replay=server.request('POST','/decide','a-business',event)
            self.assertEqual(code,200,replay);self.assertTrue(replay['idempotent_replay'])
            self.assertEqual(replay['decision_id'],first['decision_id'])
            code,denied=server.request('POST','/decide','a-business',{**event,'event_id':'new-event'})
            self.assertEqual(code,400,denied)
        finally:server.doCleanups()
