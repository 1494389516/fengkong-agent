import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from agent import governance
from agent.tenancy import AuthContext
from agent.tools.capability import RequestScope,request_scope
from agent.tool_provenance import authorize_arguments

class Provenance(unittest.TestCase):
    def test_exact_fields_scope_and_trust(self):
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);evidence=root/'evidence';evidence.mkdir()
            context=AuthContext('operator','t','a',str(evidence),'operator',('artifacts.create',),time.time()+300)
            scope=RequestScope('operator','t',str(evidence),('chart_account_timeline','model_register'),context.expires_at)
            with patch.dict(os.environ,{'FK_DATA_DIR':str(evidence),'FK_SCOPE_TENANT':'t','FK_AGENT_STATE_ROOT':str(root/'state'),'FK_AGENT_AUDIT_ROOT':str(root/'audit')}),request_scope(scope,'生成账号时间线'),governance.bind_trajectory({'run_id':'r','trust':[],'tools':[]}):
                governance.record_result('account_profile',{'uid':'u'},{'uid':'u','text':'u'})
                ref=next(iter(governance.trajectory_snapshot()['evidence']))
                governance.record_result('search_risk_knowledge',{'query':'x'},{'hits':[]})
                args={'uid':'u'};bindings={'/uid':{'ref':ref,'path':'/uid'}}
                self.assertEqual(governance.decide('chart_account_timeline',args,True).outcome,'deny')
                with authorize_arguments(context,'chart_account_timeline',args,bindings,expires_at=time.time()+60):
                    self.assertEqual(governance.decide('chart_account_timeline',args,True).outcome,'allow')
                    self.assertEqual(governance.decide('chart_account_timeline',{'uid':'v'},True).outcome,'deny')
                    self.assertEqual(governance.decide('model_register',{},True).outcome,'deny')
                    governance.record_effective_arguments('chart_account_timeline',args)
                self.assertEqual(governance.decide('chart_account_timeline',args,True).outcome,'deny')
                from agent.tool_provenance import dispatch_authorized_artifact
                from agent.tools import _REGISTRY
                with patch.dict(_REGISTRY['chart_account_timeline'],fn=lambda uid:{'uid':uid,'found':False}):
                    result=dispatch_authorized_artifact(context,'chart_account_timeline',args,bindings,expires_at=time.time()+60)
                    self.assertNotIn('error',result)
                    self.assertFalse((evidence/'.state_write.lock').exists())
                for invalid in ({'/uid':{'ref':ref,'path':'/text'}},{'/uid':{'ref':'missing','path':'/uid'}},{}):
                    with self.assertRaises(PermissionError):
                        with authorize_arguments(context,'chart_account_timeline',args,invalid,expires_at=time.time()+60):pass
                rows=[json.loads(x) for x in next((root/'audit').rglob('governance_audit.jsonl')).read_text().splitlines()]
                self.assertTrue(rows[-1]['envelope']['dependencies_digest'])
                governance.reset_trajectory('other')
                with self.assertRaises(PermissionError):
                    with authorize_arguments(context,'chart_account_timeline',args,bindings,expires_at=time.time()+60):pass

    def test_chart_name_cannot_escape_state(self):
        from agent.tools.charts import _save,plt
        with tempfile.TemporaryDirectory() as root,patch.dict(os.environ,{'FK_DATA_DIR':root+'/evidence','FK_AGENT_STATE_ROOT':root+'/state'}):
            path=Path(_save(plt.figure(),'../../escaped.png'))
            self.assertIn(Path(root)/'state',path.parents)
            self.assertTrue(path.is_file())
            self.assertFalse((Path(root)/'escaped.png').exists())

if __name__=='__main__':unittest.main()
