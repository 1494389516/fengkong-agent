import base64
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch


class IngressCompletionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.env = patch.dict(os.environ, {'FK_DATA_DIR': str(self.root/'a'),
                                           'FK_SCOPE_TENANT': 'a'})
        self.env.start(); self.addCleanup(self.env.stop)
        for tenant in ['a','b']:
            folder=self.root/tenant;folder.mkdir()
            for name, value in [('blacklist.json', []), ('events_sample.json', []), ('labels.json', {})]:
                (folder/name).write_text(json.dumps(value))
        records={}
        for tenant in ['a','b']:
            for role, perms in [('sdk',['reports.write']),('business',['decisions.write']),('agent',['cases.read'])]:
                token=tenant+'-'+role
                records[hashlib.sha256(token.encode()).hexdigest()]={
                    'principal':token, 'tenant':tenant, 'app':'app', 'data_dir':str(self.root/tenant),
                    'source_kind':'business' if role=='business' else 'sdk',
                    'permissions':perms,'expires_at':time.time()+3600,
                    'subject':'installation', 'generation':'1', 'account_id':'u',
                    'session_sha256':hashlib.sha256(b'session').hexdigest(), 'key_ids':['key']}
        self.config=self.root/'auth.json';self.config.write_text(json.dumps(records))
        os.environ['FK_AUTH_CONFIG']=str(self.config)
        self.addCleanup(os.environ.pop,'FK_AUTH_CONFIG',None)
        keys=self.root/'keys.json';keys.write_text(json.dumps({'key':base64.b64encode(bytes(range(32))).decode()}))
        identity=self.root/'identity.key';identity.write_bytes(b'x'*32)
        os.environ['FK_COLLECTOR_KEYS']=str(keys);os.environ['FK_IDENTITY_KEY_FILE']=str(identity)
        self.addCleanup(os.environ.pop,'FK_COLLECTOR_KEYS',None)
        self.addCleanup(os.environ.pop,'FK_IDENTITY_KEY_FILE',None)

    def auth(self, token):
        from agent.tenancy import authenticate
        return authenticate('Bearer '+token)

    def upload(self, report='r', nonce='n'):
        from agent.contracts.report_contract import legacy_mac, signature_input
        raw=b'{"hardware_attributes":{"model":"same"},"server_aggregates":{"devices":999},"number":1.25}'
        ts=int(time.time()*1000)
        value={'kind':'sdk_report','contract_version':1,'app_id':'app','sdk_version':'1',
            'report_id':report,'ts':ts,'nonce':nonce,'session_token':'session','sig_ver':'v3',
            'key_id':'key','device_id':'installation','scene':'login','payload_json':base64.b64encode(raw).decode(),
            'payload_sha256':base64.b64encode(hashlib.sha256(f'{len(nonce)}:{nonce}|{ts}|{len(report)}:{report}|'.encode()+raw).digest()).decode()}
        value['signature']=legacy_mac(bytes(range(32)),signature_input(value))
        return value

    def test_authenticated_tenant_routes_all_data(self):
        from agent.tenancy import data_context
        from agent.tools.datasource import data_dir
        with data_context(self.auth('b-agent')):
            self.assertEqual(data_dir(),self.root/'b')
        self.assertEqual(data_dir(),self.root/'a')

    def test_unknown_expired_and_cross_tenant_scope_rejected(self):
        from agent.tenancy import authenticate, data_context
        from agent.tools.capability import RequestScope,request_scope
        from agent.tools.datasource import data_dir
        with self.assertRaises(PermissionError): authenticate('Bearer bad')
        with data_context(self.auth('b-agent')), request_scope(RequestScope('a-agent','a',str(self.root/'a'),(),time.time()+60)):
            with self.assertRaises(PermissionError): data_dir()

    def test_collector_verifies_raw_bytes_replay_and_nonce_conflict(self):
        from agent.collector import ingest
        ctx=self.auth('a-sdk'); value=self.upload()
        first=ingest(value,ctx); second=ingest(value,ctx)
        self.assertEqual(first['evidence_id'],second['evidence_id'])
        self.assertTrue(second['idempotent_replay'])
        self.assertEqual(first['verification'],'verified_mac')
        with self.assertRaises(ValueError): ingest(self.upload('different','n'),ctx)

    def test_collector_rejects_bad_mac_scope_session_and_business_token(self):
        from agent.collector import ingest
        v=self.upload()
        for update in [{'signature':'0'*64},{'app_id':'other'},{'device_id':'other'},{'session_token':'other'}]:
            with self.assertRaises((ValueError,PermissionError)): ingest({**v,**update},self.auth('a-sdk'))
        with self.assertRaises(PermissionError): ingest(v,self.auth('a-business'))

    def test_server_entities_are_namespaced_hardware_not_identity(self):
        from agent.collector import ingest, get_observation
        a=ingest(self.upload(),self.auth('a-sdk'));b=ingest(self.upload(),self.auth('b-sdk'))
        ao=get_observation(a['evidence_id'],self.auth('a-agent'))
        bo=get_observation(b['evidence_id'],self.auth('b-agent'))
        self.assertNotEqual(ao['device_id'],bo['device_id'])
        self.assertEqual(ao['hardware_attributes'],bo['hardware_attributes'])
        self.assertNotIn('server_aggregates',ao)
        self.assertEqual(ao['identity_trust'],'server_bound')
        with self.assertRaises(PermissionError): get_observation(a['evidence_id'],self.auth('b-agent'))

    def test_business_linkage_and_case_snapshot_are_scoped_and_durable(self):
        from agent.collector import ingest, enrich_business_event
        from agent.tenancy import data_context
        from agent.tools import online_store
        from agent.investigations import consume_decision_outbox, list_cases
        r=ingest(self.upload(),self.auth('a-sdk'))
        event={'event_id':'e','uid':'u','type':'login','ts':time.time(),'report_ids':['r']}
        enriched=enrich_business_event(event,self.auth('a-business'))
        self.assertEqual(enriched['identity_trust'],'server_bound')
        with self.assertRaises(PermissionError): enrich_business_event(event,self.auth('b-business'))
        with data_context(self.auth('a-business')):
            online_store.decide(enriched,'business',lambda e,o:{'action':'review','degraded':True},
                scope=('a','app'),source_kind='business',received_at=time.time())
            consume_decision_outbox();consume_decision_outbox()
        cases=list_cases(self.auth('a-agent'))
        self.assertEqual(len(cases),1)
        self.assertIn(r['evidence_id'],cases[0]['evidence_refs'])
        self.assertEqual(list_cases(self.auth('b-agent')),[])

    def test_live_tool_history_not_seed_file(self):
        from agent.tenancy import data_context
        from agent.tools import online_store
        from agent.tools.datasource import load_events
        with data_context(self.auth('a-business')):
            online_store.decide({'event_id':'e','uid':'u','type':'login','ts':100},'p',lambda e,o:{'action':'pass'},
                scope=('a','app'),source_kind='business',received_at=110)
        with data_context(self.auth('a-agent')):
            self.assertEqual([e['event_id'] for e in load_events()],['e'])
            self.assertEqual(load_events(as_of_ts=105),[])
