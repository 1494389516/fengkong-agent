"""Cross-run review conflicts, immutable arbitration and training boundary."""
import copy
import hashlib
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from agent.evidence_snapshot import digest
from agent.tenancy import authenticate,data_context
from agent.investigations import _db
from agent.case_review import review,detail,arbitrate,export_labels,training_labels

class Arbitration(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        perms=['cases.read','cases.review','cases.arbitrate','cases.labels.export']
        registry={hashlib.sha256(p.encode()).hexdigest():dict(principal=p,tenant='t',app='a',data_dir=self.tmp.name,
                    source_kind='operator',permissions=perms,expires_at=time.time()+300)
                  for p in ('r1','r2','arbiter','worker')}
        auth=Path(self.tmp.name)/'auth.json';auth.write_text(json.dumps(registry))
        self.env=patch.dict(os.environ,{'FK_AUTH_CONFIG':str(auth),'FK_DATA_DIR':self.tmp.name});self.env.start()
        self.ctx={p:authenticate('Bearer '+p) for p in ('r1','r2','arbiter','worker')}
        self.result=dict(case_id='c',revision=1,snapshot_id='s',investigator_principal='worker')
        with data_context(self.ctx['r1']):
            db=_db();db.execute('INSERT INTO cases VALUES(?,?,?,?,?,?)',('c','t','a','u',1,json.dumps({'current_revision':1,'task_id':'task','entity_ref':'u'})))
            for task in ('task','other-run'):
                db.execute('INSERT INTO investigation_tasks(task_id,case_id,snapshot,status,result) VALUES(?,?,?,?,?)',
                    (task,'c',json.dumps(dict(case_id='c',revision=1,snapshot_id='s')),'success',json.dumps(self.result)))
            db.commit();db.close()
    def tearDown(self):
        self.env.stop();self.tmp.cleanup()
    def submit(self,principal,verdict,task='task',request_id='1'):
        return review(self.ctx[principal],dict(task_id=task,result_digest=digest(self.result),verdict=verdict,
                      note='independent evidence review',matures_at=0,request_id=request_id))
    def request(self):
        state=detail(self.ctx['arbiter'],'task')['review_state']
        return dict(task_id='task',result_digest=digest(self.result),reviews_digest=state['reviews_digest'],
                    verdict='confirmed_risk',note='resolved using independent evidence',matures_at=0,request_id='a1')
    def test_cross_run_conflict_and_arbitration(self):
        self.submit('r1','confirmed_risk');before=time.time()
        self.submit('r2','benign','other-run')
        self.assertTrue(detail(self.ctx['r1'],'task')['review_state']['disputed'])
        self.assertEqual(export_labels(self.ctx['r1'],time.time())['rows'],[])
        # Point-in-time export excludes the subsequently recorded conflicting review.
        self.assertEqual(len(export_labels(self.ctx['r1'],before)['rows']),1)
        request=self.request()
        for p in ('r1','worker'):
            with self.assertRaises(PermissionError):arbitrate(self.ctx[p],request)
        resolution=arbitrate(self.ctx['arbiter'],request)
        self.assertEqual(arbitrate(self.ctx['arbiter'],request),resolution)
        with self.assertRaisesRegex(ValueError,'unresolved conflicting'):
            arbitrate(self.ctx['arbiter'],dict(request,request_id='second-resolution'))
        bundle=export_labels(self.ctx['arbiter'],time.time())
        self.assertEqual(training_labels(bundle,'t','a')['u']['label'],'fraud')
        self.assertFalse(bundle['gold_holdout_eligible'])
        broken=copy.deepcopy(bundle);broken['rows'][0]['label']='normal'
        with self.assertRaises(ValueError):training_labels(broken,'t','a')
        with self.assertRaises(ValueError):training_labels(bundle,'other','a')
        # New evidence in the review set invalidates the old arbitration.
        self.submit('r2','benign',request_id='2')
        self.assertTrue(detail(self.ctx['r1'],'task')['review_state']['disputed'])
        self.assertEqual(export_labels(self.ctx['arbiter'],time.time())['rows'],[])
        with self.assertRaisesRegex(ValueError,'reviews changed'):
            arbitrate(self.ctx['arbiter'],dict(request,request_id='a2'))
    def test_other_unresolved_case_blocks_entity_and_history_is_immutable(self):
        import sqlite3
        self.submit('r1','confirmed_risk')
        self.assertEqual(len(export_labels(self.ctx['arbiter'],time.time())['rows']),1)
        with data_context(self.ctx['r1']):
            db=_db()
            with self.assertRaises(sqlite3.IntegrityError):db.execute('DELETE FROM case_reviews')
            db.rollback()
            db.execute('INSERT INTO cases VALUES(?,?,?,?,?,?)',('c2','t','a','u',2,json.dumps({'current_revision':1})))
            db.commit();db.close()
        self.assertEqual(export_labels(self.ctx['arbiter'],time.time())['rows'],[])

    def test_revision_and_maturity_are_not_bypassed(self):
        request=dict(task_id='task',result_digest=digest(self.result),verdict='benign',note='check',matures_at=time.time()+600,request_id='future')
        review(self.ctx['r1'],request)
        self.submit('r2','benign')
        self.assertEqual(export_labels(self.ctx['arbiter'],time.time())['rows'],[])
        with self.assertRaises(ValueError):export_labels(self.ctx['arbiter'],time.time()+1000)
        with data_context(self.ctx['r1']):
            db=_db();db.execute('UPDATE cases SET body=?',(json.dumps({'current_revision':2}),));db.commit();db.close()
        self.assertEqual(export_labels(self.ctx['arbiter'],time.time())['rows'],[])

if __name__=='__main__':unittest.main()
