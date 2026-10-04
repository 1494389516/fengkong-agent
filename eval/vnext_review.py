import copy,hashlib,json,os,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
from agent.evidence_snapshot import digest
class Review(unittest.TestCase):
    def test_review_bound_to_result_and_revision(self):
        from agent.tenancy import authenticate,data_context
        from agent.investigations import _db
        from agent.case_review import review,eligible_label
        with tempfile.TemporaryDirectory() as root:
            registry={hashlib.sha256(b'token').hexdigest():dict(principal='reviewer',tenant='t',app='a',data_dir=root,
                 source_kind='operator',permissions=['cases.read','cases.review'],expires_at=time.time()+300)}
            auth=Path(root)/'auth.json';auth.write_text(json.dumps(registry))
            with patch.dict(os.environ,{'FK_AUTH_CONFIG':str(auth),'FK_DATA_DIR':root}):
                ctx=authenticate('Bearer token')
                result={'case_id':'c','revision':1,'snapshot_id':'s','investigator_principal':'worker'}
                with data_context(ctx):
                    db=_db();db.execute('INSERT INTO cases VALUES(?,?,?,?,?,?)',('c','t','a','u',1,json.dumps({'current_revision':1})))
                    db.execute('INSERT INTO investigation_tasks(task_id,case_id,snapshot,status,result) VALUES(?,?,?,?,?)',
                        ('task','c',json.dumps(dict(case_id='c',revision=1,snapshot_id='s')),'success',json.dumps(result)))
                    db.commit();db.close()
                request=dict(task_id='task',result_digest=digest(result),verdict='confirmed_risk',note='Reviewed evidence',matures_at=time.time()+100,request_id='1')
                item=review(ctx,request);self.assertEqual(review(ctx,request),item)
                self.assertFalse(eligible_label(item,time.time()))
                self.assertTrue(eligible_label(item,time.time()+200))
                with self.assertRaises(ValueError):review(ctx,{**request,'note':'changed'})
                with data_context(ctx):
                    db=_db();db.execute('UPDATE cases SET body=?',(json.dumps({'current_revision':2}),));db.commit();db.close()
                with self.assertRaisesRegex(ValueError,'current revision'):review(ctx,{**request,'request_id':'2'})
    def test_artifact_chain_tamper(self):
        from agent.strategy_artifacts import build_chain,validate_chain
        conclusion=dict(case_id='c',revision=1,snapshot_id='s')
        review=dict(**conclusion,result_digest=digest(conclusion),verdict='confirmed_risk',label_source='human_review')
        mining={'candidates':[dict(candidate_id='C001',ast={'feature':'x','operator':'gte','value':2},train={},validation={})]}
        chain=build_chain(conclusion,review,mining,'f'*64,'C001','tenant:t/app:a')
        validate_chain(chain,'tenant:t/app:a')
        broken=copy.deepcopy(chain);broken['proposal']['ast']['value']=99
        with self.assertRaises(ValueError):validate_chain(broken)
if __name__=='__main__':unittest.main()
