import json
import os
import tempfile
import time
import unittest
from unittest.mock import patch

class LedgerContracts(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.env=patch.dict(os.environ,{'FK_DATA_DIR':self.tmp.name});self.env.start()
        from agent.investigations import _db
        self.db=_db()
        self.db.execute("INSERT INTO investigation_tasks(task_id,case_id,snapshot,status,lease_until,lease_token) VALUES('t','c','{}','running',?,'A')",(time.time()+300,));self.db.commit()
    def tearDown(self):
        self.db.close();self.env.stop();self.tmp.cleanup()
    def test_fencing_and_ambiguous_model(self):
        from agent.run_ledger import RunLedger,LeaseLost,AmbiguousExternalCall
        a=RunLedger(self.db,'t','A');self.assertIsNone(a.begin('llm:0','llm',{'x':1}))
        self.db.execute("UPDATE investigation_tasks SET lease_token='B'");self.db.commit()
        with self.assertRaises(LeaseLost):a.complete('llm:0',{'response':'late'})
        b=RunLedger(self.db,'t','B')
        with self.assertRaises(AmbiguousExternalCall):b.begin('llm:0','llm',{'x':1})
    def test_resume_read_and_settle_actual(self):
        from agent.run_ledger import RunLedger
        a=RunLedger(self.db,'t','A');a.reserve('llm:0','generator',8000,12000)
        a.begin('llm:0','llm',{'x':1});a.complete('llm:0',{'answer':'yes'},receipt='llm:0',actual=1500)
        self.assertEqual(a.usage(),dict(reserved=0,actual_used=1500,estimated_used=0))
        self.db.execute("UPDATE investigation_tasks SET lease_token='B'");self.db.commit()
        b=RunLedger(self.db,'t','B')
        self.assertEqual(b.begin('llm:0','llm',{'x':1}),{'answer':'yes'})
        b.settle('llm:0',1500);self.assertEqual(b.usage()['actual_used'],1500)
        b.reserve('llm:1','generator',8000,12000);b.settle('llm:1')
        self.assertEqual(b.usage()['estimated_used'],8000)
        with self.assertRaises(PermissionError):b.reserve('llm:2','generator',3000,12000)

    def test_agent_replays_committed_tool_after_crash(self):
        from types import SimpleNamespace as NS
        from agent.run_ledger import RunLedger
        from agent.tools.capability import investigation_constraints
        from eval.token_budget_regressions import fake_agent
        class TC:
            id='call1'
            function=NS(name='get_event_evidence',arguments='{"event_id":"e"}')
            def model_dump(self):
                return dict(id=self.id,type='function',function=dict(name=self.function.name,arguments=self.function.arguments))
        first=NS(usage=NS(prompt_tokens=100,completion_tokens=10),choices=[NS(message=NS(content=None,tool_calls=[TC()]))])
        last=NS(usage=NS(prompt_tokens=120,completion_tokens=10),choices=[NS(message=NS(content='done',tool_calls=None))])
        snapshot={'budget':{'max_tokens':12000,'max_tool_calls':12,'max_graph_nodes':100}}
        a=RunLedger(self.db,'t','A')
        original=a.complete
        def crash(node,*args,**kwargs):
            original(node,*args,**kwargs)
            if node.startswith('tool:'):raise RuntimeError('injected_after_commit')
        a.complete=crash
        agent=fake_agent([],60000);agent._run_ledger=a
        with patch('agent.core.tools.schemas',return_value=[]), patch('agent.core.tools.dispatch',return_value={'value':1}) as dispatch:
            with patch.object(agent.client,'create',return_value=first),investigation_constraints(snapshot):
                with self.assertRaisesRegex(RuntimeError,'injected_after_commit'):agent.ask('investigate')
            self.db.execute("UPDATE investigation_tasks SET lease_token='B'");self.db.commit()
            b=RunLedger(self.db,'t','B');agent=fake_agent([],60000);agent._run_ledger=b
            with patch.object(agent.client,'create',return_value=last) as model, investigation_constraints(snapshot):
                self.assertEqual(agent.ask('investigate'),'done')
                self.assertEqual(model.call_count,1)
            self.assertEqual(dispatch.call_count,1)
            self.assertEqual(b.usage()['actual_used'],240)

    def test_interleaved_agents_restore_parent_trajectory(self):
        from agent import governance
        from eval.token_budget_regressions import fake_agent
        a=fake_agent([(10,1)]*2,60000);b=fake_agent([(10,1)],60000)
        a._case_id='A';a._trajectory={'run_id':'A','trust':[],'tools':[]}
        b._case_id='B';b._trajectory={'run_id':'B','trust':['external'],'tools':[]}
        governance.reset_trajectory('parent')
        with patch('agent.core.tools.schemas',return_value=[]):
            a.ask('one');b.ask('two');a.ask('three')
        self.assertEqual(a._trajectory['run_id'],'A');self.assertEqual(a._trajectory['trust'],[])
        self.assertEqual(b._trajectory['run_id'],'B');self.assertEqual(b._trajectory['trust'],['external'])
        self.assertEqual(governance.trajectory_snapshot()['run_id'],'parent')

if __name__=='__main__':unittest.main()
