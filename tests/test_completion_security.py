import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from agent import tools
from agent.privacy import Tokenizer
from agent.tools import jobs

class CompletionSecurityTests(unittest.TestCase):
    def test_every_tool_has_closed_projection(self):
        from agent.result_schemas import RESULT_SCHEMAS
        self.assertEqual(set(RESULT_SCHEMAS), set(tools._REGISTRY))
        for name in tools._REGISTRY:
            result = Tokenizer('test').project_tool_result(name, {'new_unreviewed_field': 'private-sentinel'})
            self.assertNotIn('private-sentinel', json.dumps(result), name)
            self.assertEqual(result['schema_omitted'], 1, name)

    def test_declared_nested_values_do_not_leak_arbitrary_identity(self):
        for name in tools._REGISTRY:
            result = Tokenizer('test').project_tool_result(name, {
                'status': 'success', 'uid': 'opaque-private', 'count': 12,
                'error': 'backend exposed opaque-private',
                'result': {'uid': 'opaque-private', 'new_field': 'private-sentinel'}})
            self.assertNotIn('opaque-private', json.dumps(result), name)
            self.assertNotIn('private-sentinel', json.dumps(result), name)

    def test_global_worker_slots_include_other_process_leases(self):
        with tempfile.TemporaryDirectory() as d, patch.object(jobs, 'JOBS_DIR', Path(d)), patch.object(jobs, 'MAX_WORKERS', 1):
            jobs._save_job({'job_id': 1, 'status': 'running', 'lease_until': time.time()+60})
            jobs._save_job({'job_id': 2, 'status': 'queued', 'type': 'scan', 'params': {}})
            with patch.object(jobs._pool, 'submit') as submit:
                jobs.recover_jobs()
                self.assertFalse(submit.called)
            jobs._scheduled.clear()

    def test_projection_preserves_analytical_fields_and_roundtrip_identity(self):
        tok = Tokenizer("test")
        raw = {"uid": "arbitrary-private-id", "event_count": 8,
               "found": True, "order_amount_sum": 12.5,
               "new_unreviewed_field": "private"}
        result = tok.project_tool_result("feature_stats", raw)
        self.assertEqual(result["event_count"], 8)
        self.assertEqual(result["order_amount_sum"], 12.5)
        self.assertIs(result["found"], True)
        self.assertEqual(tok.detokenize(result["uid"]), raw["uid"])
        self.assertEqual(result["schema_omitted"], 1)

    def test_numeric_identifiers_use_dimension_contract(self):
        result = Tokenizer("test").project_tool_result("blacklist_query", {
            "result": {"dimension": "uid", "value": 123456789}})
        self.assertNotIn("123456789", json.dumps(result))

    def test_investigation_scope_and_call_budget_are_runtime_enforced(self):
        from agent.tools.capability import investigation_constraints
        snapshot = {'entity_ref': 'u_1', 'as_of': 50, 'budget': {'max_tool_calls': 1, 'max_graph_nodes': 3, 'max_tokens': 100}}
        with investigation_constraints(snapshot):
            with patch.dict(tools._REGISTRY, {'feature_stats': {'fn': lambda **kw: kw}}):
                self.assertIn('error', tools.dispatch('feature_stats', {'uid': 'u_other'}))
                self.assertIn('error', tools.dispatch('feature_stats', {'uid': 'u_1'}))

    def test_investigation_pins_time_and_rejects_graph_over_budget(self):
        from agent.tools.capability import investigation_constraints
        snapshot = {'entity_ref':'u_1', 'as_of':50, 'budget':{'max_tool_calls':4,'max_graph_nodes':1,'max_tokens':100}}
        with investigation_constraints(snapshot), patch.dict(tools._REGISTRY, {'feature_stats': {'fn':lambda **kw:kw}}):
            result=tools.dispatch('feature_stats', {'uid':'u_1','as_of_ts':999}, projection=False)
            self.assertEqual(result['as_of_ts'],50)
            with patch('agent.tools.datasource.load_events', return_value=[{'uid':'u_1','device_id':'d1','ts':10}]):
                self.assertIn('error',tools.dispatch('graph_relations',{'uid':'u_1'}))

    def test_investigation_token_budget_blocks_before_network_and_caps_output(self):
        from agent.core import Agent
        from agent.tools.capability import investigation_constraints, RequestScope, request_scope
        from types import SimpleNamespace
        from unittest.mock import Mock
        agent = Agent.__new__(Agent)
        agent._privacy = False
        agent.messages = []
        agent.model = 'test'
        agent.strict_mode = False
        agent.tool_pack = 'full'
        agent._trim_tool_messages = lambda: None
        agent._estimate_context_tokens = lambda: 0
        agent._accumulate = lambda usage: None
        agent._maybe_checkpoint = lambda: None
        agent._log_ask = lambda *args: None
        response=SimpleNamespace(usage=None,choices=[SimpleNamespace(message=SimpleNamespace(tool_calls=None,content='done'))])
        create=Mock(return_value=response)
        agent.client=SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
        snapshot={'entity_ref':'u','as_of':50,'budget':{'max_tool_calls':1,'max_graph_nodes':2,'max_tokens':100}}
        scope=RequestScope('p','t','d',('feature_stats',),time.time()+60)
        with request_scope(scope), investigation_constraints(snapshot):
            with self.assertRaisesRegex(PermissionError,'token budget'):
                agent._ask_loop('x'*200,None,None,None)
        create.assert_not_called()
        snapshot['budget']['max_tokens']=20000
        with request_scope(scope), investigation_constraints(snapshot) as state:
            self.assertEqual(agent._ask_loop('inspect',None,None,None),'done')
            self.assertLessEqual(state['tokens'],20000)
            self.assertGreater(state['tokens'],0)
        self.assertLessEqual(create.call_args.kwargs['max_tokens'],2048)
