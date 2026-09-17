"""Independent public HTTP contract + tenant/evidence/decision acceptance."""
import http.client
import json
from pathlib import Path
import shutil
import sqlite3
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
import test_completion_ingress as fixtures
import serve

class CompletionHTTP(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.IngressCompletionTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        for tenant in ('a','b'):
            for p in (Path(__file__).resolve().parents[1]/'data').glob('*.json'):
                target=self.fixture.root/tenant/p.name
                if not target.exists(): shutil.copyfile(p,target)
        (self.fixture.root/'a'/'blacklist.json').write_text(json.dumps([
            {'dimension':'uid','value':'u','list':'black','reason':'independent seeded evidence','added_at':'2020-01-01'}]))
        self.server=ThreadingHTTPServer(('127.0.0.1',0),serve.Handler)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)

    def stop(self):
        self.server.shutdown();self.server.server_close();self.thread.join(3)

    def request(self,method,path,token,body=None,raw=None):
        conn=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=4)
        try:
            payload=raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
            conn.request(method,path,body=payload,headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
            r=conn.getresponse();return r.status,json.loads(r.read())
        finally: conn.close()

    def test_public_report_decision_case_and_domain_isolation(self):
        upload=self.fixture.upload()
        raw=json.dumps(upload,ensure_ascii=False,indent=2).encode()
        code,receipt=self.request('POST','/reports','a-sdk',raw=raw)
        self.assertEqual(code,200,receipt)
        db=sqlite3.connect(self.fixture.root/'a'/'online.sqlite3')
        try:
            saved=db.execute('SELECT raw_envelope FROM evidence WHERE evidence_id=?',(receipt['evidence_id'],)).fetchone()
            self.assertEqual(saved[0],raw)
        finally: db.close()
        event={'event_id':'same-event','uid':'u','type':'login','ts':time.time(),'report_ids':['r']}
        code,wrong=self.request('POST','/decide','a-sdk',event)
        self.assertIn(code,(401,403),wrong)
        code,wrong=self.request('POST','/reports','a-business',upload)
        self.assertIn(code,(401,403),wrong)
        code,foreign=self.request('POST','/decide','b-business',event)
        self.assertIn(code,(400,403),foreign)
        code,a=self.request('POST','/decide','a-business',event)
        self.assertEqual(code,200,a);self.assertEqual(a['tenant_id'],'a');self.assertEqual(a['action'],'reject')
        code,replay=self.request('POST','/decide','a-business',event)
        self.assertEqual(code,200,replay);self.assertTrue(replay['idempotent_replay'])
        self.assertEqual(replay['decision_id'],a['decision_id'])
        code,b_report=self.request('POST','/reports','b-sdk',upload)
        self.assertEqual(code,200,b_report);self.assertNotEqual(receipt['evidence_id'],b_report['evidence_id'])
        code,b=self.request('POST','/decide','b-business',event)
        self.assertEqual(code,200,b);self.assertEqual(b['action'],'pass',b)
        self.assertNotEqual(a['decision_id'],b['decision_id'])
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=6) as pool:
            checks=list(pool.map(lambda tenant:(tenant,self.request('POST','/decide',tenant+'-business',event)), ['a','b']*6))
        for tenant,(status,result) in checks:
            self.assertEqual(status,200,result)
            self.assertEqual(result['tenant_id'],tenant)
            self.assertEqual(result['decision_id'],a['decision_id'] if tenant=='a' else b['decision_id'])
        code,a_cases=self.request('GET','/cases','a-agent')
        self.assertEqual(code,200,a_cases);self.assertIn(receipt['evidence_id'],json.dumps(a_cases))
        code,b_cases=self.request('GET','/cases','b-agent')
        self.assertEqual(code,200,b_cases);self.assertNotIn(receipt['evidence_id'],json.dumps(b_cases))
        code,forged=self.request('POST','/decide','b-business',{**event,'event_id':'forged','identity_trust':'server_bound','entity_generation':'x'})
        self.assertEqual(code,400,forged)

    def test_scoped_credential_cannot_read_default_dataset_brief(self):
        for token in ('a-sdk','b-business','b-agent'):
            with self.subTest(token=token):
                status,body=self.request('GET','/brief',token)
                self.assertEqual(status,403,body)

    def test_anonymous_health_does_not_disclose_default_policy(self):
        status,body=self.request('GET','/health','invalid')
        self.assertEqual(status,200,body)
        self.assertNotIn('policy_version',body)
        self.assertNotIn('readiness',body)
