import contextvars
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from agent.tools import capability, packs, jobs
from agent import tools
from agent.privacy import Tokenizer


class FusionSecurityTests(unittest.TestCase):
    def tearDown(self):
        capability.clear_user_text()

    def test_c16_empty_context_denies_write(self):
        capability.clear_user_text()
        self.assertTrue(capability.enforce('build_dataset', True))

    def test_c17_pack_is_context_local(self):
        packs.set_active_pack('graph')
        child = contextvars.copy_context()
        child.run(packs.set_active_pack, 'full')
        self.assertEqual(packs.current(), 'graph')
        packs.set_active_pack('full')

    def test_c20_full_result_separate_from_projection(self):
        with patch.dict(tools._REGISTRY, {'scan_all': {'fn': lambda: list(range(1000))}}):
            self.assertEqual(len(tools.dispatch('scan_all', {}, projection=False)), 1000)
            self.assertEqual(len(tools.dispatch('scan_all', {})), 21)

    def test_c21_graph_identifiers_and_ipv6(self):
        raw = {'accounts': ['arbitrary-account'], 'ips': ['2001:db8::1'],
               'devices': ['serial-123'], 'known_labels': {'arbitrary-account': 'bot'},
               'device_flags': {'serial-123': ['flag']}, 'text': 'address 2001:db8::1'}
        safe = json.dumps(Tokenizer('test').tokenize_data(raw))
        for value in ['arbitrary-account', '2001:db8::1', 'serial-123']:
            self.assertNotIn(value, safe)

    def test_c19_error_is_failure(self):
        with tempfile.TemporaryDirectory() as d, patch.object(jobs, 'JOBS_DIR', Path(d)):
            jobs._save_job({'job_id': 1, 'status': 'queued', 'type': 'scan', 'params': {}})
            with patch.object(tools, 'dispatch', return_value={'error': 'denied'}):
                jobs._execute(1, 'scan', {})
            self.assertEqual(jobs._load_job(1)['status'], 'failed')

    def scope(self, *names):
        return capability.RequestScope('tester', 'tenant-a', 'dataset-a', tuple(names), time.time() + 120)

    def test_c16_generic_submit_cannot_export(self):
        with capability.request_scope(self.scope('job_submit', 'build_dataset'), '提交任务'):
            self.assertIn('error', jobs.job_submit('dataset_build'))

    def test_c16_expired_and_cross_scope_denied(self):
        scope = capability.RequestScope('tester', 't', 'd', ('scan_all',), time.time() - 1)
        with capability.request_scope(scope):
            self.assertTrue(capability.enforce('scan_all', True))
        with capability.request_scope(self.scope('scan_all')):
            self.assertFalse(jobs._authorized({'authorization': {'principal': 'other', 'tenant': 'tenant-a', 'dataset': 'dataset-a'}}))

    def test_c18_pool_and_backlog_bounded(self):
        self.assertEqual(jobs._pool._max_workers, jobs.MAX_WORKERS)
        with tempfile.TemporaryDirectory() as d, patch.object(jobs, 'JOBS_DIR', Path(d)), patch.object(jobs, 'MAX_PENDING', 1):
            jobs._save_job({'job_id': 1, 'status': 'queued'})
            with capability.request_scope(self.scope('job_submit', 'scan_all'), '提交任务'):
                self.assertIn('budget', jobs.job_submit('scan')['error'])

    def test_c18_expired_worker_reclaimed_and_mutation_dead_lettered(self):
        with tempfile.TemporaryDirectory() as d, patch.object(jobs, 'JOBS_DIR', Path(d)):
            for jid, kind in [(1, 'scan'), (2, 'dataset_build')]:
                jobs._save_job({'job_id': jid, 'status': 'running', 'type': kind,
                    'params': {}, 'lease_until': 0, 'attempts': 1,
                    'authorization': self.scope('scan_all').snapshot()})
            with patch.object(jobs._pool, 'submit') as submit:
                jobs.recover_jobs()
                self.assertEqual(submit.call_count, 1)
                self.assertEqual(jobs._load_job(1)['attempts'], 2)
                self.assertTrue(jobs._load_job(2)['dead_letter'])
            jobs._scheduled.clear()

    def test_c20_job_persists_1000_results(self):
        with tempfile.TemporaryDirectory() as d, patch.object(jobs, 'JOBS_DIR', Path(d)):
            jobs._save_job({'job_id': 1, 'status': 'queued'})
            with patch.dict(tools._REGISTRY, {'scan_all': {'fn': lambda: list(range(1000))}}):
                jobs._execute(1, 'scan', {})
            job = jobs._load_job(1)
            self.assertEqual(len(json.loads(Path(job['result_path']).read_text())), 1000)

    def test_c21_typed_graph_edges_and_list_evidence(self):
        raw = {'edge_evidence': [{'source': ['uid', 'arbitrary-account'], 'target': ['device_id', 'serial-123']}],
               'blacklist_hits': ['uid=arbitrary-account(black)'],
               'blacklist_evidence': [{'dimension': 'device_id', 'value': 'serial-123'}]}
        safe = json.dumps(Tokenizer('test').tokenize_data(raw))
        self.assertNotIn('arbitrary-account', safe)
        self.assertNotIn('serial-123', safe)

    def test_c21_graph_schema_omits_unknown_fields(self):
        payload = {'components': [{'accounts': ['private-id'],
                                   'new_unreviewed_field': 'private-id'}],
                   'chart_path': '/out/private-id.png', 'new_field': 'secret'}
        safe = Tokenizer('test').project_tool_result('graph_relations', payload)
        self.assertNotIn('private-id', json.dumps(safe))
        self.assertNotIn('secret', json.dumps(safe))
        self.assertEqual(safe['schema_omitted'], 2)
        self.assertEqual(safe['components'][0]['schema_omitted'], 1)

    def test_c17_same_agent_concurrent_ask_rejected(self):
        import threading
        from agent.core import Agent
        agent = Agent.__new__(Agent)
        agent._ask_lock = threading.Lock()
        agent._ask_lock.acquire()
        try:
            with self.assertRaisesRegex(RuntimeError, 'concurrent'):
                agent.ask('hello')
        finally:
            agent._ask_lock.release()
