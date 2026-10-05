"""Budget work boundaries and opt-in operator pricing; no network providers."""
import unittest
from unittest.mock import patch
from eval import vnext_ledger as ledger_fixture
from agent.run_ledger import RunLedger,_current
from agent.resource_budget import ResourceBudgetExceeded

class Resources(unittest.TestCase):
    setUp=ledger_fixture.LedgerContracts.setUp
    tearDown=ledger_fixture.LedgerContracts.tearDown
    def test_persistent_scan_limit_and_price_ceiling(self):
        from agent.tools.datasource import event_snapshot,load_events
        ledger=RunLedger(self.db,'t','A')
        ledger.configure_budget({'max_tokens':12000,'max_scanned_rows':2,'max_input_bytes':10000,
            'pricing':{'version':'test-price','rates_nano_usd_per_token':dict(generator=2,embedding=3,verifier=2),'max_cost_nano_usd':20000}})
        token=_current.set(ledger)
        try:
            with event_snapshot([dict(uid='u',ts=1),dict(uid='v',ts=2)],'s'):
                self.assertEqual(len(load_events()),2)
                with self.assertRaises(ResourceBudgetExceeded):load_events()
            self.assertEqual(ledger.resource_usage()['scanned_rows'],2)
            ledger.reserve('first','generator',8000,12000)
            self.assertEqual(ledger.cost_usage()['reserved_nano_usd'],16000)
            ledger.settle('first',1500)
            self.assertEqual(ledger.cost_usage()['usage_bound_nano_usd'],3000)
            ledger.reserve('second','verifier',8000,12000)
            with self.assertRaises(ResourceBudgetExceeded):ledger.reserve('third','embedding',500,12000)
            self.assertIsNone(self.db.execute("SELECT receipt_id FROM budget_receipts WHERE receipt_id='third'").fetchone())
        finally:_current.reset(token)

    def test_budget_is_not_swallowed_by_verifier(self):
        from agent.rag.entailment import evaluate_report_entailment
        ledger=RunLedger(self.db,'t','A');token=_current.set(ledger)
        class E:
            def evaluate(self,*args):raise ResourceBudgetExceeded('test budget')
        try:
            with self.assertRaises(ResourceBudgetExceeded):
                evaluate_report_entailment({'claims':[{'statement':'x','knowledge_citations':['[K:k]']}]},
                                          {'k':{'text':'premise'}},evaluator=E())
        finally:_current.reset(token)

    def test_generator_overreported_usage_includes_other_components(self):
        from eval.token_budget_regressions import fake_agent
        from agent.tools.capability import investigation_constraints
        ledger=RunLedger(self.db,'t','A')
        ledger.reserve('embedding-prior','embedding',1000,12000);ledger.settle('embedding-prior',1000)
        agent=fake_agent([(11500,0)],60000);agent._run_ledger=ledger
        snapshot={'budget':dict(max_tokens=12000,max_tool_calls=12,max_graph_nodes=100)}
        with patch('agent.core.tools.schemas',return_value=[]),investigation_constraints(snapshot):
            with self.assertRaises(ResourceBudgetExceeded):agent.ask('investigate')
        self.assertEqual(ledger.usage()['actual_used'],12500)

    def test_unknown_provider_response_interrupts_and_retains_reservation(self):
        from agent.run_ledger import metered_call,AmbiguousExternalCall
        ledger=RunLedger(self.db,'t','A');ledger.max_tokens=12000
        token=_current.set(ledger)
        def unavailable():raise TimeoutError('response lost')
        try:
            with self.assertRaises(AmbiguousExternalCall):metered_call('embedding',{'text':'x'},100,unavailable)
            self.assertEqual(ledger.usage()['reserved'],100)
            with self.assertRaises(AmbiguousExternalCall):metered_call('embedding',{'text':'x'},100,lambda: self.fail('must not call twice'))
        finally:_current.reset(token)

    def test_graph_work_is_charged_and_output_budget_stops_dispatch(self):
        from agent.tools.datasource import event_snapshot
        from agent.tools.graph import _build_graph
        from agent.tools import dispatch,_REGISTRY
        ledger=RunLedger(self.db,'t','A')
        ledger.configure_budget(dict(max_graph_nodes_total=2,max_graph_edges_total=1,max_output_bytes=10))
        token=_current.set(ledger)
        try:
            with event_snapshot([dict(uid='u',device_id='d',ts=1)],'s'):
                graph=_build_graph(as_of_ts=2)
                self.assertEqual(len(graph),2)
                with self.assertRaises(ResourceBudgetExceeded):_build_graph(as_of_ts=2)
            with patch.dict(_REGISTRY['get_event_evidence'],fn=lambda **_:dict(value='x'*30)):
                with self.assertRaises(ResourceBudgetExceeded):dispatch('get_event_evidence',{'event_id':'e'})
        finally:_current.reset(token)

if __name__=='__main__':unittest.main()
