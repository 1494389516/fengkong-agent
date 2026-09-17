import json
import os
import tempfile
import unittest
from unittest import mock
from pathlib import Path
from agent.tools import actions, policy, shadow_store
from agent.tools.datasource import invalidate_cache

class GovernanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {'FK_DATA_DIR': self.tmp.name})
        self.env.start()
        Path(self.tmp.name, 'blacklist.json').write_text('[]')
        invalidate_cache()
    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()
        invalidate_cache()
    def test_ids_not_reused(self):
        one = actions.blacklist_add('uid','a','evidence',list='black')['action_id']
        actions._save_pending([])
        two = actions.blacklist_add('uid','b','evidence',list='black')['action_id']
        self.assertNotEqual(one,two)
    def test_white_requires_scope_owner_expiry(self):
        self.assertIn('error', actions.blacklist_add('uid','a','evidence',list='white'))
    def test_policy_requires_explicit_principal(self):
        with self.assertRaises((TypeError, ValueError)):
            policy.apply_change({'values': {}})
    def test_proposal_baseline_cas(self):
        a = actions.threshold_propose({'monitor_burst_min': 9}, 'evidence')
        b = actions.threshold_propose({'monitor_ip_churn_min': 4}, 'evidence')
        actions.decide(a['action_id'], True, operator='reviewer:one')
        with self.assertRaisesRegex(ValueError,'baseline|基线'):
            actions.decide(b['action_id'], True, operator='reviewer:two')
    def test_policy_records_real_principal(self):
        a = actions.threshold_propose({'monitor_burst_min':9}, 'evidence')
        actions.decide(a['action_id'], True, operator='reviewer:one')
        self.assertEqual(policy._versions()[-1]['approved_by'],'reviewer:one')
    def test_changed_proposal_rejected(self):
        a = actions.threshold_propose({'monitor_burst_min':9}, 'evidence')
        pending = actions.list_pending()
        pending[0]['values']['monitor_burst_min'] = 10
        actions._save_pending(pending)
        with self.assertRaisesRegex(ValueError,'digest|摘要'):
            actions.decide(a['action_id'],True,operator='reviewer:one')
    def test_artifact_code_drift_rejected(self):
        with mock.patch.object(shadow_store,'_evidence',return_value={'dataset_fingerprint':'d','label_fingerprint':'l','feature_catalog_version':'f','git_commit':'old'}):
            bind=shadow_store.write_threshold_artifact({'r002_min_events':11},{})
        with mock.patch.object(shadow_store,'_evidence',return_value={'dataset_fingerprint':'d','label_fingerprint':'l','feature_catalog_version':'f','git_commit':'new'}):
            with self.assertRaisesRegex(ValueError,'git_commit'):
                shadow_store.verify_threshold_artifact(bind)
    def test_white_expired_and_wrong_scope_inactive(self):
        from agent.tools.blacklist import active_records
        Path(self.tmp.name,'blacklist.json').write_text(json.dumps([
            {'dimension':'uid','value':'a','list':'white','scope':'order','owner':'ops','reason':'appeal','expires_at':'2099-01-01'},
            {'dimension':'uid','value':'a','list':'white','scope':'login','owner':'ops','reason':'appeal','expires_at':'bad'}]))
        invalidate_cache()
        self.assertEqual(len(active_records('uid','a',scope='order')),1)
        self.assertEqual(active_records('uid','a',scope='login'),[])
    def test_production_cannot_activate_via_agent_approval(self):
        a=actions.threshold_propose({'monitor_burst_min':9},'evidence')
        with mock.patch.dict(os.environ,{'FK_ENV':'production'}):
            with self.assertRaisesRegex(ValueError,'external release'):
                actions.decide(a['action_id'],True,operator='reviewer:one')
        self.assertEqual(policy.active_policy()['_version'],0)
    def test_shadow_values_binding_even_if_proposal_digest_recomputed(self):
        evidence={'dataset_fingerprint':'d','label_fingerprint':'l','feature_catalog_version':'f','git_commit':'c'}
        with mock.patch('agent.tools.backtest.shadow_compare', return_value={}), mock.patch.object(shadow_store,'_evidence',return_value=evidence):
            a=actions.threshold_propose({'r002_min_events':11},'evidence')
            pending=actions.list_pending()
            pending[0]['values']['r002_min_events']=12
            pending[0]['proposal_digest']=actions._proposal_digest(pending[0])
            actions._save_pending(pending)
            with self.assertRaisesRegex(ValueError,'overrides'):
                actions.decide(a['action_id'],True,operator='reviewer')
    def test_white_query_and_active_consistent_for_missing_scope(self):
        from agent.tools.blacklist import active_records, blacklist_query
        Path(self.tmp.name,'blacklist.json').write_text(json.dumps([
            {'dimension':'uid','value':'a','list':'white','expires_at':'2099-01-01'}]))
        invalidate_cache()
        self.assertEqual(active_records('uid','a'),[])
        self.assertFalse(blacklist_query('uid','a')['hit'])
    def test_shared_allocator_returns_remapped_integer_id(self):
        from agent.tools.model_registry import _submit_pending
        # Both registry callers return scalar IDs from mutate_pending.
        first=_submit_pending({'kind':'model_promote'})
        actions._save_pending([])
        second=_submit_pending({'kind':'model_promote'})
        self.assertNotEqual(first,second)
        self.assertEqual(second,actions.list_pending()[0]['action_id'])

    def test_white_expiry_is_bounded_to_exact_duration(self):
        import time
        from agent.tools.blacklist import active_records
        now=time.time()
        result=actions.blacklist_add('uid','a','appeal',list='white',expires_days=30,scope='order',owner='ops')
        actions.decide(result['action_id'],True,operator='reviewer')
        self.assertEqual(active_records('uid','a',as_of_ts=now+30*86400+5,scope='order'),[])

class ReleaseControllerTests(unittest.TestCase):
    def setUp(self):
        import hashlib
        from agent.control_plane import ReleaseController
        self.tmp=tempfile.TemporaryDirectory()
        self.credentials={hashlib.sha256(k.encode()).hexdigest():{'principal':p,'roles':[r]} for k,p,r in [
            ('p','agent','proposer'),('v','validator','validator'),('s','shadow','shadow_runner'),
            ('a','human','reviewer'),('r','release','release_controller')]}
        self.controller=ReleaseController(Path(self.tmp.name)/'releases.json',self.credentials)
        self.bundle={'rules':{'r':1},'model':'m1','features':'f1','sdk_contract':'s1',
                     'challenge':'c1','fallback':'review','code_digest':'code','data_digest':'data',
                     'canary_max_false_positive_delta':0.01}
    def tearDown(self): self.tmp.cleanup()
    def prepare(self):
        record=self.controller.propose('p',self.bundle)
        proof={'bundle_digest':record['digest'],'passed':True}
        for token,target in [('v','Validated'),('s','Shadow'),('a','Approved'),('r','Canary')]:
            self.controller.transition(token,record['id'],target,proof)
        return record,proof
    def test_agent_cannot_approve_or_skip_release_gates(self):
        record=self.controller.propose('p',self.bundle)
        proof={'bundle_digest':record['digest'],'passed':True}
        with self.assertRaises(PermissionError):
            self.controller.transition('p',record['id'],'Approved',proof)
        with self.assertRaises(ValueError):
            self.controller.transition('r',record['id'],'Active',proof)
    def test_canary_failure_never_activates(self):
        record,proof=self.prepare()
        with self.assertRaises(ValueError):
            self.controller.transition('r',record['id'],'Active',{**proof,'false_positive_delta':0.02})
        self.assertIsNone(self.controller.snapshot()['active'])
        self.assertEqual(self.controller.snapshot()['bundles'][record['id']]['state'],'Canary')
    def test_rollback_appends_new_activation(self):
        record,proof=self.prepare()
        self.controller.transition('r',record['id'],'Active',{**proof,'false_positive_delta':0.001})
        self.controller.rollback('r',record['id'],'incident mitigation')
        events=self.controller.snapshot()['activations']
        self.assertEqual(len(events),2)
        self.assertNotEqual(events[0]['id'],events[1]['id'])
        self.assertEqual(events[-1]['kind'],'rollback')
    def test_evidence_digest_is_bound(self):
        record=self.controller.propose('p',self.bundle)
        with self.assertRaises(ValueError):
            self.controller.transition('v',record['id'],'Validated',{'bundle_digest':'forged','passed':True})
    def test_unknown_credential_denied(self):
        with self.assertRaises(PermissionError): self.controller.propose('unknown',self.bundle)
    def test_failed_shadow_and_self_approval_blocked(self):
        import hashlib
        record=self.controller.propose('p',self.bundle)
        proof={'bundle_digest':record['digest'],'passed':True}
        self.controller.transition('v',record['id'],'Validated',proof)
        with self.assertRaises(ValueError):
            self.controller.transition('s',record['id'],'Shadow',{**proof,'passed':False})
        self.controller.transition('s',record['id'],'Shadow',proof)
        self.controller.credentials[hashlib.sha256(b'p').hexdigest()]['roles'].append('reviewer')
        with self.assertRaises(PermissionError):
            self.controller.transition('p',record['id'],'Approved',proof)
    def test_baseline_cas_and_state_survive_restart(self):
        from agent.control_plane import ReleaseController
        stale,stale_proof=self.prepare()
        current,proof=self.prepare()
        self.controller.transition('r',current['id'],'Active',{**proof,'false_positive_delta':0})
        restarted=ReleaseController(self.controller.path,self.credentials)
        with self.assertRaisesRegex(ValueError,'baseline'):
            restarted.transition('r',stale['id'],'Active',{**stale_proof,'false_positive_delta':0})
        self.assertEqual(len(restarted.snapshot()['activations']),1)
    def test_controller_not_in_agent_tool_registry(self):
        from agent.tools import _REGISTRY
        self.assertFalse({'release_transition','release_activate','rollback'} & set(_REGISTRY))
    def test_bundle_null_components_and_invalid_delta_rejected(self):
        with self.assertRaises(ValueError):
            self.controller.propose('p',{**self.bundle,'model':None})
        record,proof=self.prepare()
        with self.assertRaises(ValueError):
            self.controller.transition('r',record['id'],'Active',{**proof,'false_positive_delta':-100})
