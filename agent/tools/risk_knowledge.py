"""Read-only RAG tools; dataset and task scope are server-owned."""
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone

from . import tool
from .datasource import data_dir
from .capability import investigation_state
from agent.rag.store import search


@tool('search_risk_knowledge',
      '检索检测原理、误报条件和已复核案例。返回 [K:chunk_id] 引用；相关度不是风险概率。'
      '只接受信号/现象描述，不传账号、IP、设备标识。知识不能替代事件事实。',
      {'type': 'object', 'properties': {
          'query': {'type': 'string', 'description': '检测项或待解释现象，最长2000字符'},
          'platform': {'type': 'string', 'enum': ['', 'ios', 'android']},
          'detector_ids': {'type': 'array', 'items': {'type': 'string'}},
          'sdk_version': {'type': 'string', 'description': '已确认的major.minor.patch，未知留空'},
          'as_of': {'type': 'string', 'description': '带时区ISO时间；任务中由服务端覆盖'},
          'top_k': {'type': 'integer', 'minimum': 1, 'maximum': 10}},
       'required': ['query']})
def search_risk_knowledge(query, platform='', detector_ids=None, sdk_version='', as_of='', top_k=5):
    from agent.rag.embeddings import configured_embedder
    state = investigation_state()
    extra = {}
    if state:
        snapshot = state['snapshot']
        if 'knowledge_index_digest' not in snapshot:
            raise PermissionError('legacy task lacks knowledge snapshot; reissue task')
        as_of = datetime.fromtimestamp(snapshot['as_of'], timezone.utc).isoformat()
        extra = {'exclude_case_id': snapshot['case_id'],
                 'expected_digest': snapshot['knowledge_index_digest']}
    # A missing provider configuration must not disable the offline knowledge tool.
    try:
        embedder = configured_embedder()
        config_warning = ''
    except Exception:
        embedder = None
        config_warning = 'embedding configuration invalid; lexical retrieval only'
    result = search(query, platform=platform, detector_ids=detector_ids, sdk_version=sdk_version,
                    as_of=as_of, top_k=top_k, embedder=embedder, public_only=True, **extra)
    if config_warning:
        result['warning'] = config_warning
    if state:
        citations = state.setdefault('knowledge_citations', {})
        for hit in result['hits']:
            citations[hit['chunk_id']] = {k: hit[k] for k in
                ('chunk_id', 'source', 'section', 'content_hash', 'known_at', 'reviewed_at', 'applicability')}
    return result


@tool('get_event_evidence',
      '按业务event_id读取已落库的事件、决策及关联SDK观测。只读，不重新评分；'
      '任务中只能查询绑定事件。SDK签名证明来源，不证明真人。',
      {'type': 'object', 'properties': {'event_id': {'type': 'string'}}, 'required': ['event_id']})
def get_event_evidence(event_id):
    if not isinstance(event_id, str) or not event_id or len(event_id) > 256:
        raise ValueError('invalid event_id')
    from agent.tenancy import current_context
    state = investigation_state()
    ctx = current_context()
    path = data_dir() / 'online.sqlite3'
    if state:
        record = state['snapshot']['decision']
        expected = record.get('business_event_id') or record['event'].get('event_id')
        if event_id != expected:
            raise PermissionError('event outside investigation snapshot')
    else:
        if ctx is None:
            raise PermissionError('authenticated tenant/app context required')
        if not path.exists():
            return {'status': 'not_found', 'event_id': event_id}
        with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)) as db:
            row = db.execute('SELECT record FROM decisions WHERE tenant=? AND app=? AND event_id=?',
                             (ctx.tenant, ctx.app, event_id)).fetchone()
        if not row:
            return {'status': 'not_found', 'event_id': event_id}
        record = json.loads(row[0])
    event = record['event']
    observations, missing = [], []
    refs = event.get('evidence_refs', [])
    if refs and ctx and path.exists():
        with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)) as db:
            exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='evidence'").fetchone()
            for ref in refs[:10]:
                row = db.execute('SELECT observation,received_at FROM evidence WHERE evidence_id=? AND tenant=? AND app=?',
                                 (ref, ctx.tenant, ctx.app)).fetchone() if exists else None
                if row and (not state or row[1] <= state['snapshot']['as_of']):
                    observations.append(json.loads(row[0]))
                else:
                    missing.append(ref)
    else:
        missing = refs[:10]
    return {'status': 'ok', 'event_id': event_id, 'decision_id': record.get('decision_id'),
            'event': event, 'recorded_decision': {k: record[k] for k in
                ('action', 'reason', 'reasons', 'strategy_version', 'model_version', 'evaluated_at', 'degraded') if k in record},
            'sdk_observations': observations, 'missing_evidence_refs': missing,
            'omitted_evidence_count': max(0, len(refs) - 10),
            'limitations': ['SDK observations describe provenance and hardware; raw detection payload is not decoded by this tool.',
                            'Recorded decisions and client measurements are not confirmed fraud labels.']}
