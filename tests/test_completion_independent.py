"""Independent acceptance probes: exercise persisted/process boundaries."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]

class IndependentCompletionTests(unittest.TestCase):
    def test_killed_worker_recovers_durable_read_job(self):
        """SIGKILL after claim, then a new interpreter resumes the real scan tool."""
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            data = base / 'data'
            shutil.copytree(ROOT / 'data', data)
            job_dir = base / 'jobs'
            job_dir.mkdir()
            env = dict(os.environ, FK_DATA_DIR=str(data), FK_SCOPE_TENANT='independent',
                       PYTHONPATH=str(ROOT))
            script = '''
import json, sys, time
from pathlib import Path
from agent.tools import jobs
from agent.tools.capability import RequestScope, request_scope
jobs.JOBS_DIR = Path(sys.argv[1])
jobs.LEASE_SECONDS = 0.3
if sys.argv[2] == 'submit':
    import os
    os.environ['FK_JOB_TEST_GATE'] = '1'
    scope = RequestScope('verifier', 'independent', os.environ['FK_DATA_DIR'],
                         ('job_submit', 'scan_all'), time.time()+60)
    with request_scope(scope, '提交任务'):
        print(json.dumps(jobs.job_submit('scan')), flush=True)
else:
    jobs.recover_jobs()
while True:
    time.sleep(.02)
'''
            first = subprocess.Popen([sys.executable, '-u', '-c', script, str(job_dir), 'submit'],
                                     cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     text=True)
            second = None
            try:
                row = first.stdout.readline()
                self.assertTrue(row, first.stderr.read() if first.poll() is not None else 'no receipt')
                response = json.loads(row)
                self.assertIn('job_id', response, response)
                job_path = job_dir / ('job_%06d.json' % response['job_id'])
                deadline = time.monotonic()+5
                while time.monotonic() < deadline:
                    record = json.loads(job_path.read_text())
                    if record.get('started_at'):
                        break
                    time.sleep(.02)
                self.assertEqual(record['status'], 'running')
                first.kill()
                first.wait(timeout=5)
                time.sleep(.4)
                second = subprocess.Popen([sys.executable, '-u', '-c', script, str(job_dir), 'recover'],
                                          cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                          text=True)
                deadline = time.monotonic()+15
                while time.monotonic() < deadline:
                    record = json.loads(job_path.read_text())
                    if record['status'] in ('success', 'failed'):
                        break
                    time.sleep(.03)
                self.assertEqual(record['status'], 'success', record)
                self.assertEqual(record['attempts'], 2)
                result = json.loads(Path(record['result_path']).read_text())
                self.assertIsInstance(result, dict)
                self.assertNotIn('error', result)
            finally:
                for process in (first, second):
                    if process is not None:
                        if process.poll() is None:
                            process.kill()
                        process.communicate(timeout=5)

    def test_governed_publish_changes_real_engine_and_rollback(self):
        """A real signed activation must affect rule_eval, not only reader state."""
        import hashlib
        from unittest.mock import patch
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        from agent.control_plane import ReleaseController, digest
        from agent.release_publisher import publish
        from agent.tools.featurelib import FEATURE_CATALOG_VERSION
        from agent import engine
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            shutil.copytree(ROOT / 'data', base / 'data')
            key = Ed25519PrivateKey.generate()
            (base/'key').write_bytes(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            (base/'pub').write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo))
            creds = {hashlib.sha256(t.encode()).hexdigest(): {
                'principal':t, 'roles':[r], 'scopes':['tenant:a'], 'expires_at':time.time()+600}
                for t,r in [('p','proposer'),('v','validator'),('s','shadow_runner'),
                            ('a','reviewer'),('r','release_controller')]}
            controller = ReleaseController(base/'journal', creds, strict=True, scope='tenant:a')
            def activate(version, score):
                bundle = {'rules':{'R007':1}, 'model':{'name':'verified','version':version,
                    'scores':{'independent-uid':{'score':score,'model_version':'verified '+version}}},
                    'features':FEATURE_CATALOG_VERSION, 'sdk_contract':'sdk-v1',
                    'challenge':'disabled', 'fallback':'review', 'code_digest':'code',
                    'data_digest':'data', 'canary_max_false_positive_delta':.01,
                    'policy':{}, 'strategy':{}, 'feature':{'catalog_version':FEATURE_CATALOG_VERSION},
                    'list':{'records':[]}, 'graph':{}, 'versions':{'policy':version,'model':version,
                      'feature':FEATURE_CATALOG_VERSION, 'list':'1','graph':'1','strategy':'1'}}
                record = controller.propose('p', bundle)
                evidence = {'scope':'tenant:a','expires_at':time.time()+60,'sample_count':100}
                proof = {'bundle_digest':record['digest'],'passed':True,
                    'baseline_activation':record['baseline_activation'], 'evidence':evidence,
                    'evidence_digest':digest(evidence),'false_positive_delta':0}
                for token, state in [('v','Validated'),('s','Shadow'),('a','Approved'),
                                     ('r','Canary'),('r','Active')]:
                    controller.transition(token, record['id'], state, proof)
                publish(base/'journal', base/'published', base/'key')
                return record
            with patch.dict(os.environ, {'FK_DATA_DIR':str(base/'data'),
                    'FK_RUNTIME_BUNDLE_DIR':str(base/'published'),
                    'FK_RUNTIME_PUBLIC_KEY':str(base/'pub'), 'FK_ENGINE_MODE':'local'}):
                first = activate('v1', .99)
                event = {'event_id':'independent','uid':'independent-uid','type':'login','ts':time.time()}
                rejected = engine.evaluate_event(event, use_current_policy=True)
                self.assertEqual(rejected['action'], 'reject', rejected)
                self.assertEqual(rejected['model_version'], 'verified v1')
                activate('v2', .01)
                passed = engine.evaluate_event(event, use_current_policy=True)
                self.assertEqual(passed['action'], 'pass', passed)
                self.assertNotEqual(rejected['runtime_activation_id'], passed['runtime_activation_id'])
                controller.rollback('r', first['id'], 'rollback acceptance')
                publish(base/'journal', base/'published', base/'key')
                rolled = engine.evaluate_event(event, use_current_policy=True)
                self.assertEqual(rolled['action'], 'reject', rolled)
                self.assertNotEqual(rolled['runtime_activation_id'], rejected['runtime_activation_id'])

    def test_transaction_snapshot_keeps_knowledge_time_for_late_events(self):
        from unittest.mock import patch
        from agent.tools import online_store
        from agent.tools.featurelib import account_features
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {'FK_DATA_DIR':tmp}):
            for eid, occurred, received in [('late',100,300),('replay',200,400)]:
                event={'event_id':eid,'uid':'same','type':'coupon_claim','ts':occurred}
                def compute(event, operator):
                    return {'action':'pass','features':account_features('same',as_of_ts=event['ts'])}
                record, _ = online_store.decide(event,'verifier',compute,
                    scope=('a','app'),source_kind='business',received_at=received)
            self.assertFalse(record['features']['found'], record['features'])

    def test_investigation_receives_actual_case_context_and_scope(self):
        import test_completion_ingress as fixture_module
        from agent.collector import ingest, enrich_business_event
        from agent.tenancy import data_context
        from agent.tools import online_store
        from agent.investigations import consume_decision_outbox, list_cases, run_task
        fixture = fixture_module.IngressCompletionTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        registry = json.loads(fixture.config.read_text())
        import hashlib
        record = registry[hashlib.sha256(b'a-agent').hexdigest()]
        record['permissions'].append('cases.run')
        record['tools'] = ['account_profile', 'feature_stats', 'graph_relations']
        fixture.config.write_text(json.dumps(registry))
        receipt = ingest(fixture.upload(), fixture.auth('a-sdk'))
        event = enrich_business_event({'event_id':'case-event','uid':'u','type':'login',
            'ts':time.time(),'report_ids':['r']}, fixture.auth('a-business'))
        with data_context(fixture.auth('a-business')):
            online_store.decide(event,'business',lambda e,o:{'action':'review'},
                scope=('a','app'),source_kind='business',received_at=time.time())
            consume_decision_outbox()
        case = list_cases(fixture.auth('a-agent'))[0]
        captured = {}
        class RecordingAgent:
            def ask(self, prompt, **kwargs):
                captured.update(prompt=prompt, decoded=self._tok.detokenize(prompt), **kwargs)
                return 'investigated'
        result = run_task(case['task_id'], fixture.auth('a-agent'), agent_factory=RecordingAgent)
        self.assertEqual(result['status'], 'success')
        self.assertIn('case-event', captured['decoded'])
        self.assertNotIn('case-event', captured['prompt'])
        self.assertEqual(result['evidence_refs'], [receipt['evidence_id']])
        self.assertEqual(captured['scope'].tenant, 'a')
        with self.assertRaises(PermissionError):
            run_task(case['task_id'], fixture.auth('b-agent'), agent_factory=RecordingAgent)

    def test_every_registered_outbound_schema_blocks_pii_fixtures(self):
        """Each registered schema is probed; this does not execute each tool."""
        import copy
        from agent import tools
        from agent.privacy import Tokenizer
        from agent.result_schemas import RESULT_SCHEMAS, GRAPH_TOP
        self.assertEqual(set(tools._REGISTRY), set(RESULT_SCHEMAS))
        secrets = ['customer-Z9_private', '203.0.113.219', '2001:db8:42::7',
                   'private.person@example.invalid', 'serial-private-Z9',
                   '+86 13912345678', 'unknown-private-field', '91928374650192837465']
        free_text = 'backend context ' + ' | '.join(secrets)
        nested = {'uid': secrets[0], 'ip': secrets[1], 'ip_address': secrets[2],
                  'email': secrets[3], 'device_id': secrets[4], 'phone': secrets[5],
                  'description': free_text, 'new_unreviewed_field': secrets[6],
                  'accounts': [secrets[0], int(secrets[7])],
                  'known_labels': {secrets[0]: 'fraud'},
                  'count': 7, 'status': 'success',
                  'result': {'note': free_text, 'unknown_child': secrets[6],
                             'dimension': 'uid', 'value': int(secrets[7])}}
        for name in sorted(tools._REGISTRY):
            with self.subTest(schema=name):
                tokenizer = Tokenizer('independent-schema-fixture')
                fields = GRAPH_TOP if name == 'graph_relations' else RESULT_SCHEMAS[name]
                numeric_field = 'component_count' if name == 'graph_relations' else 'count'
                enum_field = 'next_action' if name == 'graph_relations' else 'status'
                enum_value = 'continue' if name == 'graph_relations' else 'success'
                self.assertIn(numeric_field, fields)
                self.assertIn(enum_field, fields)
                payload = {**nested, numeric_field: 7, enum_field: enum_value,
                           'error': copy.deepcopy(nested),
                           'components': [{**nested, 'accounts':[secrets[0]],
                               'edge_evidence':[{'source':['uid', secrets[0]],
                                                 'target':['ip', secrets[2]]}]}]}
                original = copy.deepcopy(payload)
                safe = tokenizer.project_tool_result(name, payload)
                wire = json.dumps(safe, ensure_ascii=False)
                for secret in secrets:
                    self.assertNotIn(secret, wire)
                self.assertEqual(safe[numeric_field], 7)
                self.assertEqual(safe[enum_field], enum_value)
                self.assertEqual(payload, original)
                # The known nested error carrier itself must be transformed,
                # not merely hidden by dropping the entire top-level fixture.
                self.assertIn('error', safe)
                self.assertEqual(safe['error']['count'], 7)
                self.assertEqual(safe['error']['status'], 'success')
                self.assertEqual(tokenizer.detokenize(safe['error']['uid']), secrets[0])
