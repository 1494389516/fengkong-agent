import copy
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from agent.rag import store
from agent.rag.reporting import citation_audit
from agent import tools
from agent.tools import capability, packs
from agent.privacy import Tokenizer


class VectorFixture:
    """Test vectors exercise fusion/cache, not real embedding quality."""
    identity = 'test-fixture-v1'
    def __init__(self):
        self.calls = []
    def embed(self, texts):
        self.calls.append(list(texts))
        return [[1.0, .1] if 'debugger' in t else [.1, 1.0] for t in texts]


class RagTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.corpus = self.root / 'corpus'; self.corpus.mkdir()
        env = patch.dict(os.environ, {'FK_DATA_DIR': str(self.root / 'data'), 'FK_RAG_EMBED_ENABLED': '0'})
        env.start(); self.addCleanup(env.stop)
        self.doc = dict(knowledge_id='debugger', type='detector_doc', title='debugger 调试',
            status='reviewed', platform='ios', source='https://example.invalid/code',
            known_at='2020-01-01T00:00:00Z', reviewed_at='2020-01-01T00:00:00Z',
            review_basis='test fixture', caveats='合法调试也可能触发，不能认定欺诈。',
            applicability='test only', simulated=False, export_policy='public_reference',
            detector_ids=['DebuggerDetector'], sdk_version_min=None, sdk_version_max=None,
            sections=[{'heading':'原理','text':'debugger 硬件断点检测与授权调试。'}])
        self.write(self.doc)

    def write(self, doc, filename='a.json'):
        (self.corpus / filename).write_text(json.dumps(doc, ensure_ascii=False))

    def snapshot(self):
        return dict(case_id='case1', entity_ref='u', as_of=1609459200,
                    decision={'business_event_id':'e1','event':{'event_id':'e1','uid':'u'}},
                    knowledge_index_digest=store.read_index()[0].get('index_digest',''),
                    budget={'max_tool_calls':3,'max_tokens':2000,'max_graph_nodes':10})

    def test_exact_and_chinese_retrieval_carries_caveats(self):
        store.ingest(self.corpus)
        for query in ('DebuggerDetector', '硬件断点'):
            hit = store.search(query, platform='ios')['hits'][0]
            self.assertEqual(hit['knowledge_id'], 'debugger')
            self.assertEqual(hit['caveats'], self.doc['caveats'])
            self.assertTrue(hit['citation'].startswith('[K:debugger-'))
        self.assertEqual(store.search('zzzz_no_such_signal')['status'], 'no_match')
        self.assertFalse(store.search('debugger', platform='android')['hits'])

    def test_time_status_simulated_and_self_case_filters(self):
        for field, value in [('known_at','2099-01-01T00:00:00Z'),
                             ('reviewed_at','2099-01-01T00:00:00Z'),
                             ('status','draft'), ('status','withdrawn'), ('simulated',True)]:
            doc = {**self.doc, field:value}; self.write(doc); store.ingest(self.corpus)
            self.assertFalse(store.search('debugger', as_of='2021-01-01T00:00:00Z')['hits'])
        self.write({**self.doc,'case_id':'case1'}); store.ingest(self.corpus)
        self.assertFalse(store.search('debugger', exclude_case_id='case1')['hits'])

    def test_versions_fail_closed_when_missing_or_outside_range(self):
        self.write({**self.doc,'sdk_version_min':'1.2.0','sdk_version_max':'1.9.0'})
        store.ingest(self.corpus)
        for v in ('','1.1.0','2.0.0'):
            self.assertFalse(store.search('debugger',sdk_version=v)['hits'])
        self.assertTrue(store.search('debugger',sdk_version='1.5.0')['hits'])
        with self.assertRaises(ValueError): store.search('debugger',sdk_version='1.x')

    def test_atomic_failure_preserves_old_index(self):
        store.ingest(self.corpus); before = store.read_index()
        bad = copy.deepcopy(self.doc); bad['sections'][0]['text'] = 'x' * 601
        self.write(bad)
        with self.assertRaises(ValueError): store.ingest(self.corpus)
        self.assertEqual(before, store.read_index())

    def test_rebuild_removes_deleted_and_changes_citations(self):
        self.write({**self.doc,'knowledge_id':'other'},'b.json'); store.ingest(self.corpus)
        old = store.search('debugger')['hits'][0]['chunk_id']
        (self.corpus/'b.json').unlink()
        self.write({**self.doc,'title':'debugger updated'}); store.ingest(self.corpus)
        rows = store.read_index()[1]
        self.assertEqual(len(rows),1); self.assertNotEqual(rows[0]['chunk_id'],old)

    def test_embedding_cache_hybrid_and_explicit_failure(self):
        provider = VectorFixture(); store.ingest(self.corpus, provider)
        self.assertEqual(len(provider.calls),1)
        store.ingest(self.corpus, provider); self.assertEqual(len(provider.calls),1)
        result = store.search('debugger', embedder=provider)
        self.assertEqual(result['mode'],'bm25+vector')
        with patch.object(provider,'embed',side_effect=TimeoutError):
            result = store.search('debugger',embedder=provider)
            self.assertEqual(result['mode'],'bm25'); self.assertTrue(result['warning'])
        provider.identity = 'different'
        self.assertIn('mismatch',store.search('debugger',embedder=provider)['warning'])

    def test_embedding_failure_does_not_replace_index(self):
        store.ingest(self.corpus); before=store.read_index()
        provider=VectorFixture()
        with patch.object(provider,'embed',return_value=[[float('nan')]]):
            with self.assertRaises(ValueError): store.ingest(self.corpus,provider)
        self.assertEqual(before,store.read_index())

    def test_dataset_isolation(self):
        store.ingest(self.corpus)
        with patch.dict(os.environ,{'FK_DATA_DIR':str(self.root/'other')}):
            self.assertFalse(store.search('debugger')['hits'])
            self.assertFalse((self.root/'other').exists())

    def test_task_forces_time_and_pins_index(self):
        store.ingest(self.corpus); snapshot=self.snapshot()
        self.write({**self.doc,'known_at':'2022-01-01T00:00:00Z'});store.ingest(self.corpus)
        snapshot['knowledge_index_digest']=store.read_index()[0]['index_digest']
        with capability.investigation_constraints(snapshot),packs.request_pack('investigate'):
            result=tools.dispatch('search_risk_knowledge',{'query':'debugger','as_of':'2099-01-01T00:00:00Z'},projection=False)
            self.assertFalse(result['hits'])
        self.write(self.doc);store.ingest(self.corpus)
        with capability.investigation_constraints(snapshot):
            result=tools.dispatch('search_risk_knowledge',{'query':'debugger'},projection=False)
            self.assertIn('index changed',result['error'])

    def test_task_event_and_call_budget(self):
        store.ingest(self.corpus)
        with capability.investigation_constraints(self.snapshot()):
            self.assertIn('error',tools.dispatch('get_event_evidence',{'event_id':'different'}))
            self.assertEqual(tools.dispatch('get_event_evidence',{'event_id':'e1'},projection=False)['event']['uid'],'u')
            tools.dispatch('search_risk_knowledge',{'query':'debugger'})
            self.assertIn('budget',tools.dispatch('search_risk_knowledge',{'query':'debugger'})['error'])

    def test_private_knowledge_not_exported_or_embedded(self):
        self.write({**self.doc,'export_policy':'local_only'});store.ingest(self.corpus)
        self.assertTrue(store.search('debugger')['hits'])
        self.assertFalse(tools.dispatch('search_risk_knowledge',{'query':'debugger'},projection=False)['hits'])
        provider=VectorFixture()
        with self.assertRaises(ValueError): store.ingest(self.corpus,provider)
        self.assertFalse(provider.calls)

    def test_public_text_and_citation_survive_privacy_boundary(self):
        store.ingest(self.corpus)
        result=tools.dispatch('search_risk_knowledge',{'query':'debugger'})
        safe=Tokenizer('test').project_tool_result('search_risk_knowledge',result)
        hit=safe['hits'][0]
        self.assertIn('硬件断点',hit['text'])
        self.assertIn('⟦用户内容⟧',hit['text'])
        self.assertTrue(hit['citation'].startswith('[K:'))
        self.assertIn('合法调试',hit['caveats'])
        private=copy.deepcopy(result); private['hits'][0]['export_policy']='local_only'
        self.assertNotIn('硬件断点',json.dumps(Tokenizer('test').project_tool_result('search_risk_knowledge',private),ensure_ascii=False))

    def test_only_retrieved_citations_are_accepted(self):
        result=citation_audit('说明 [K:a] 和伪造 [K:fake]',{'a':{'source':'test'}})
        self.assertEqual(result['unknown_chunk_ids'],['fake'])
        self.assertFalse(result['semantic_support_verified'])
        self.assertEqual(citation_audit('缺证据',{})['status'],'no_citations')

    def test_registration_is_read_only_and_scoped(self):
        for name in ('search_risk_knowledge','get_event_evidence'):
            self.assertEqual(capability.level_of(name),'read')
            self.assertIn(name,packs.tool_names('investigate'))
            self.assertNotIn(name,packs.tool_names('strategy'))
        self.assertNotIn('ingest',tools._REGISTRY)
        scope=capability.RequestScope('p','a',str(self.root/'data'),(),time.time()+60)
        with capability.request_scope(scope):
            self.assertIn('denied',tools.dispatch('search_risk_knowledge',{'query':'debugger'})['error'].replace('insufficient request scope','denied'))

    def test_validation_rejects_duplicate_timezone_and_limits(self):
        self.write(self.doc,'b.json')
        with self.assertRaises(ValueError): store.ingest(self.corpus)
        for kwargs in ({'top_k':True},{'top_k':11},{'as_of':'2026-01-01'},{'detector_ids':'wrong'}):
            with self.assertRaises(ValueError): store.search('debugger',**kwargs)


class RagInvestigationIntegrationTests(unittest.TestCase):
    def test_worker_reads_authorized_event_retrieves_and_records_citation(self):
        import hashlib
        import test_completion_ingress as fixtures
        from agent.tenancy import data_context
        from agent.tools import online_store
        from agent.investigations import consume_decision_outbox, list_cases, run_task
        fixture=fixtures.IngressCompletionTests(); fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        registry=json.loads(fixture.config.read_text())
        entry=registry[hashlib.sha256(b'a-agent').hexdigest()]
        entry['permissions'].append('cases.run')
        entry['tools']=['get_event_evidence','search_risk_knowledge']
        fixture.config.write_text(json.dumps(registry))
        corpus=fixture.root/'knowledge';corpus.mkdir()
        seed=json.loads((Path(__file__).resolve().parents[1]/'knowledge/detectors/debugger.json').read_text())
        seed['known_at']=seed['reviewed_at']='2020-01-01T00:00:00Z'
        (corpus/'detector.json').write_text(json.dumps(seed))
        with data_context(fixture.auth('a-business')):
            store.ingest(corpus)
            online_store.decide({'event_id':'rag-event','uid':'u','type':'login','ts':time.time()},
                'business',lambda e,o:{'action':'review'},scope=('a','app'),source_kind='business',received_at=time.time())
            consume_decision_outbox()
        case=list_cases(fixture.auth('a-agent'))[0]
        observed={}
        class ToolUsingAgent:
            def ask(self, prompt, scope):
                with capability.request_scope(scope),packs.request_pack('investigate'):
                    facts=tools.dispatch('get_event_evidence',{'event_id':'rag-event'},projection=False)
                    knowledge=tools.dispatch('search_risk_knowledge',{'query':'DebuggerDetector'},projection=False)
                    observed.update(facts=facts,knowledge=knowledge)
                    return '存在授权调试的正常解释，需补查。'+knowledge['hits'][0]['citation']
        result=run_task(case['task_id'],fixture.auth('a-agent'),agent_factory=ToolUsingAgent)
        self.assertEqual(observed['facts']['event_id'],'rag-event')
        self.assertEqual(result['budget_used']['tool_calls'],2)
        self.assertEqual(result['knowledge_citation_audit']['status'],'references_present')
        self.assertTrue(result['knowledge_citation_audit']['citations'])
        self.assertFalse(result['knowledge_citation_audit']['semantic_support_verified'])
        with data_context(fixture.auth('b-agent')):
            self.assertEqual(tools.dispatch('get_event_evidence',{'event_id':'rag-event'},projection=False)['status'],'not_found')
            self.assertFalse(tools.dispatch('search_risk_knowledge',{'query':'DebuggerDetector'},projection=False)['hits'])
        # Completed worker replay is idempotent and does not call the Agent again.
        self.assertEqual(run_task(case['task_id'],fixture.auth('a-agent'),agent_factory=lambda: self.fail('must not rerun')),result)


if __name__ == '__main__': unittest.main()
