"""Focused production-module regressions: python -m eval.audit_20260923."""
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from agent.tools import online_store, featurelib
from agent.compute_budget import feature_budget, ComputeBudgetExceeded
from agent.collector import _decode_mapping, issue_challenge, _database
from agent.contracts.report_contract import ContractError
from agent.tenancy import AuthContext, data_context
from agent.rag.workflow import begin_search, finish_search, retrieval_audit
from agent.rag.reporting import claim_evidence_audit


class AuditRegression(unittest.TestCase):
    def test_scoped_history_and_window(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, FK_DATA_DIR=directory):
            db = online_store.connect()
            def row(i, uid, ts):
                e = dict(event_id=str(i), uid=uid, ts=ts, recorded_at=ts, type='login')
                return ('t', 'a', str(i), ts, ts, json.dumps(e))
            db.executemany('INSERT INTO events VALUES (?,?,?,?,?,?)',
                           [row(i, 'unrelated', 1) for i in range(12000)] +
                           [row(12000+i, 'old', 1) for i in range(1100)] +
                           [row(14000, 'old', 99)])
            db.commit(); db.close()
            def run(uid, window=None):
                def compute(e, operator):
                    f = featurelib.account_features(e['uid'], e['ts'], window)
                    return {'action': 'pass', 'features_snapshot': f}
                return online_store.decide(dict(event_id='new-'+uid+str(window), uid=uid, ts=100),
                    'test', compute, scope=('t','a'), source_kind='business', received_at=100)[0]
            fresh = run('fresh')
            self.assertEqual(fresh['action'], 'pass')
            self.assertFalse(fresh['features_snapshot']['found'])
            selected = run('old', 10)
            self.assertEqual(selected['features_snapshot']['event_count'], 1)
            # The genuine full-history dependency is not silently sampled.
            full = run('old')
            self.assertEqual(full['action'], 'review')
            self.assertEqual(full['degraded_reason'], 'account_event_limit')
            self.assertIsNone(full['feature_snapshot_id'])

    def test_recursive_mapping(self):
        table = {'h':'hardware_attributes','m':'model','c':'cpu_count'}
        payload = {'h':{'m':'device','c':6}, 'items':[{'m':'nested'}]}
        decoded = _decode_mapping(payload, table, 'all')
        self.assertEqual(decoded['hardware_attributes'], {'model':'device','cpu_count':6})
        self.assertEqual(decoded['items'], [{'model':'nested'}])
        self.assertEqual(_decode_mapping(payload, table, 'topLevel')['hardware_attributes'], payload['h'])
        with self.assertRaises(ContractError):
            _decode_mapping({'h':{'m':'x','model':'y'}}, table, 'all')
        deep = {}; root = deep
        for _ in range(18):
            root['x'] = {}; root = root['x']
        with self.assertRaises(ContractError): _decode_mapping(deep, table, 'all')

    def test_counterevidence_failure_and_zero_hits(self):
        state = {'event_evidence_loaded':True, 'snapshot':{}}
        begin_search(state, {'query':'support','purpose':'support'})
        finish_search(state, {'status':'ok','hits':[{'chunk_id':'k'}]})
        begin_search(state, {'query':'counter','purpose':'counterevidence'})
        finish_search(state, error='TimeoutError')
        audit = retrieval_audit(state)
        self.assertEqual(audit['outcome'], 'counterevidence_incomplete')
        self.assertEqual(audit['attempt_count'], 2)
        self.assertTrue(audit['counterevidence_attempted'])
        self.assertFalse(audit['counterevidence_search_performed'])
        summary = json.dumps(dict(verdict='evidence_gap', claims=[], missing_evidence=[], recommended_next_step='retry'))
        _, result = claim_evidence_audit(summary, {}, {}, audit)
        self.assertIn('retrieval failed or unfinished; evidence coverage unknown', result['workflow_issues'])
        state['retrieval_trace'].pop()
        begin_search(state, {'query':'counter','purpose':'counterevidence'})
        finish_search(state, {'status':'no_match','hits':[]})
        audit = retrieval_audit(state)
        self.assertEqual(audit['outcome'], 'balanced')
        self.assertTrue(audit['counterevidence_search_performed'])
        self.assertFalse(audit['counterevidence_hit'])

    def test_live_challenge_is_not_replaced(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, FK_AUTH_CONFIG=''):
            registry = Path(directory) / 'auth.json'
            registry.write_text(json.dumps({'a'*64: dict(principal='p', tenant='t', app='a', data_dir=directory, source_kind='sdk', permissions=['reports.write'], expires_at=time.time()+3600)}))
            os.environ['FK_AUTH_CONFIG'] = str(registry)
            ctx = AuthContext('p','t','a',directory,'sdk',('reports.write',),time.time()+3600)
            from concurrent.futures import ThreadPoolExecutor
            def request():
                try: return issue_challenge(ctx, now=100)
                except ContractError: return None
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda _: request(), range(2)))
            self.assertEqual(sum(row is not None for row in results), 1)
            first = next(row for row in results if row is not None)
            with self.assertRaisesRegex(ContractError, 'already in flight'):
                issue_challenge(ctx, now=101)
            with data_context(ctx):
                db = _database()
                self.assertEqual(db.execute('SELECT challenge_id,consumed FROM attestation_challenges').fetchall(), [(first['challenge_id'],0)])
                db.execute('UPDATE attestation_challenges SET consumed=1'); db.commit(); db.close()
            second = issue_challenge(ctx, now=102)
            self.assertNotEqual(first['challenge_id'], second['challenge_id'])
            third = issue_challenge(ctx, now=223)
            self.assertNotEqual(second['challenge_id'], third['challenge_id'])


if __name__ == '__main__': unittest.main()
