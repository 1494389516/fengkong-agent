"""Authenticated case review, revision-bound and separate from production action."""
from .storage import postgres, begin_write, local_schema, table_names, order_column, json_text
import json
import math
import time
import uuid
from .tenancy import data_context
from .evidence_snapshot import digest
from .investigations import _db


def detail(context,task_id):
    context.require('cases.read')
    with data_context(context):
        db=_db(readonly=True)
        try:
            row=db.execute('SELECT t.snapshot,t.result,t.status,c.body FROM investigation_tasks t JOIN cases c ON c.case_id=t.case_id '
                'WHERE t.task_id=? AND c.tenant=? AND c.app=?',(task_id,context.tenant,context.app)).fetchone()
            if not row:raise PermissionError('task outside authorized domain')
            snapshot,result,status,case=row
            result=json.loads(result) if result else None
            return {'task_id':task_id,'snapshot':json.loads(snapshot),'result':result,'status':status,
                    'case':json.loads(case),'result_digest':digest(result),
                    'review_state':_review_state(db,json.loads(snapshot))}
        finally:db.close()


def review(context,request):
    context.require('cases.review')
    required={'task_id','result_digest','verdict','note','matures_at','request_id'}
    if not isinstance(request,dict) or set(request)!=required:raise ValueError('invalid review contract')
    if request['verdict'] not in ('confirmed_risk','benign','insufficient'):raise ValueError('invalid review verdict')
    if not isinstance(request['note'],str) or not 1<=len(request['note'])<=4000:raise ValueError('review rationale required')
    if not isinstance(request['request_id'],str) or not 1<=len(request['request_id'])<=128:raise ValueError('request id required')
    maturity=request['matures_at']
    if type(maturity) not in (int,float) or not math.isfinite(maturity) or maturity<0:raise ValueError('invalid label maturity')
    with data_context(context):
        db=_db()
        try:
            _review_schema(db)
            begin_write(db)
            fingerprint=digest(request)
            old=db.execute('SELECT request_digest,body FROM case_reviews WHERE principal=? AND request_id=?',
                           (context.principal,request['request_id'])).fetchone()
            if old:
                if old[0]!=fingerprint:raise ValueError('review idempotency conflict')
                return json.loads(old[1])
            row=db.execute('SELECT t.snapshot,t.result,t.status,c.body FROM investigation_tasks t JOIN cases c ON c.case_id=t.case_id '
                'WHERE t.task_id=? AND c.tenant=? AND c.app=?',(request['task_id'],context.tenant,context.app)).fetchone()
            if not row:raise PermissionError('task outside authorized domain')
            snapshot=json.loads(row[0]);result=json.loads(row[1]) if row[1] else None;case=json.loads(row[3])
            if row[2]!='success' or not isinstance(result,dict):raise ValueError('completed result required')
            if digest(result)!=request['result_digest']:raise ValueError('result changed')
            if snapshot.get('revision',1)!=case.get('current_revision',1):raise ValueError('new evidence requires review of current revision')
            investigator=result.get('investigator_principal')
            if not investigator or context.principal in _investigators(db,snapshot['case_id']):
                raise PermissionError('independent reviewer required')
            body={'review_id':uuid.uuid4().hex,'tenant_id':context.tenant,'app_id':context.app,
                  'case_id':snapshot['case_id'],'revision':snapshot.get('revision',1),'snapshot_id':snapshot['snapshot_id'],
                  'task_id':request['task_id'],'result_digest':request['result_digest'],'reviewer':context.principal,
                  'verdict':request['verdict'],'note':request['note'],'reviewed_at':time.time(),
                  'label_source':'human_review','matures_at':maturity,'disputed':False,
                  'production_action_authorized':False}
            db.execute('INSERT INTO case_reviews VALUES(?,?,?,?,?,?)',
                       (body['review_id'],request['task_id'],context.principal,request['request_id'],fingerprint,json.dumps(body)))
            db.commit();return body
        except BaseException:
            db.rollback();raise
        finally:db.close()


def eligible_label(review_record,as_of):
    if not isinstance(review_record,dict):return False
    times=(as_of,review_record.get('reviewed_at'),review_record.get('matures_at'))
    if any(type(t) not in (int,float) or not math.isfinite(t) or t<0 for t in times):return False
    return (review_record.get('label_source') in ('human_review','human_arbitration')
            and review_record.get('disputed') is False
            and review_record.get('verdict') in ('confirmed_risk','benign')
            and times[1]<=as_of and times[2]<=as_of)


def new_run(context,case_id,revision):
    """Explicit new inference for a pinned revision, never masquerading as replay."""
    context.require('cases.run')
    if type(revision) is not int or revision<1:raise ValueError('invalid revision')
    with data_context(context):
        db=_db()
        try:
            begin_write(db)
            row=db.execute('SELECT r.body,c.body FROM case_revisions r JOIN cases c ON c.case_id=r.case_id '
                'WHERE r.case_id=? AND r.revision=? AND c.tenant=? AND c.app=?',
                (case_id,revision,context.tenant,context.app)).fetchone()
            if not row:raise PermissionError('revision outside authorized domain')
            task_id=uuid.uuid4().hex
            db.execute("INSERT INTO investigation_tasks(task_id,case_id,snapshot,status) VALUES(?,?,?,'queued')",
                       (task_id,case_id,row[0]))
            case=json.loads(row[1])
            if revision==case.get('current_revision',1):
                case['task_id']=task_id
                db.execute('UPDATE cases SET body=? WHERE case_id=?',(json.dumps(case),case_id))
            db.commit();return {'task_id':task_id,'mode':'new_inference','revision':revision}
        except BaseException:db.rollback();raise
        finally:db.close()


def _investigators(db,case_id):
    # Review decisions are combined across inference runs. Independence must
    # therefore cover the case, not just the result selected in the workbench.
    return {json.loads(raw).get('investigator_principal') for (raw,) in db.execute(
        'SELECT result FROM investigation_tasks WHERE case_id=? AND result IS NOT NULL',(case_id,))}


def _review_schema(db):
    if postgres(db):
        return
    db.executescript("""
      CREATE TABLE IF NOT EXISTS case_reviews(
        review_id TEXT PRIMARY KEY, task_id TEXT, principal TEXT, request_id TEXT,
        request_digest TEXT, body TEXT, UNIQUE(principal,request_id));
      CREATE TABLE IF NOT EXISTS case_arbitrations(
        arbitration_id TEXT PRIMARY KEY, case_id TEXT, revision INTEGER,
        principal TEXT, request_id TEXT, request_digest TEXT, body TEXT,
        UNIQUE(principal,request_id));
    """)

    for table in ('case_reviews','case_arbitrations'):
        for action in ('UPDATE','DELETE'):
            db.execute(f"CREATE TRIGGER IF NOT EXISTS {table}_{action.lower()}_immutable "
                       f"BEFORE {action} ON {table} BEGIN SELECT RAISE(ABORT,'review history is immutable'); END")
    db.commit()


def _review_state(db, snapshot, as_of=None):
    """Resolve all reviews of this revision, including separate inference runs.

    Arbitration binds the exact review set. A subsequent review invalidates that
    resolution without changing or deleting any historical review.
    """
    tables=table_names(db)
    records=[]
    if 'case_reviews' in tables:
        for (raw,) in db.execute('SELECT r.body FROM case_reviews r JOIN investigation_tasks t '
                                'ON t.task_id=r.task_id WHERE t.case_id=?',(snapshot['case_id'],)):
            record=json.loads(raw)
            if record['revision']==snapshot.get('revision',1):
                records.append(record)
    if as_of is not None:
        records=[r for r in records if r['reviewed_at']<=as_of]
    records.sort(key=lambda r:r['review_id'])
    fingerprint=digest(records)
    verdicts={r['verdict'] for r in records}
    disputed=len(verdicts)>1
    resolution=None
    if 'case_arbitrations' in tables:
        for (raw,) in db.execute('SELECT body FROM case_arbitrations WHERE case_id=? AND revision=?',
                                (snapshot['case_id'],snapshot.get('revision',1))):
            item=json.loads(raw)
            if item['reviews_digest']==fingerprint and (as_of is None or item['reviewed_at']<=as_of):
                if resolution is None or (item['reviewed_at'],item['arbitration_id'])>(resolution['reviewed_at'],resolution['arbitration_id']):
                    resolution=item
    effective=resolution or (max(records,key=lambda r:(r['reviewed_at'],r['review_id'])) if records and not disputed else None)
    if effective:
        effective=dict(effective,disputed=False)
        effective['matures_at']=max([effective['matures_at']]+[r['matures_at'] for r in records])
    return {'reviews':records,'reviews_digest':fingerprint,'disputed':disputed and resolution is None,
            'resolution':resolution,'effective_label':effective}


def arbitrate(context,request):
    context.require('cases.arbitrate')
    required={'task_id','result_digest','reviews_digest','verdict','note','matures_at','request_id'}
    if not isinstance(request,dict) or set(request)!=required:raise ValueError('invalid arbitration contract')
    if request['verdict'] not in ('confirmed_risk','benign','insufficient'):raise ValueError('invalid verdict')
    if not isinstance(request['note'],str) or not 1<=len(request['note'])<=4000:raise ValueError('rationale required')
    if not isinstance(request['request_id'],str) or not 1<=len(request['request_id'])<=128:raise ValueError('request id required')
    maturity=request['matures_at']
    if type(maturity) not in (int,float) or not math.isfinite(maturity) or maturity<0:raise ValueError('invalid maturity')
    with data_context(context):
        db=_db()
        try:
            _review_schema(db)
            begin_write(db)
            old=db.execute('SELECT request_digest,body FROM case_arbitrations WHERE principal=? AND request_id=?',
                           (context.principal,request['request_id'])).fetchone()
            if old:
                if old[0]!=digest(request):raise ValueError('arbitration idempotency conflict')
                return json.loads(old[1])
            row=db.execute('SELECT t.snapshot,t.result,t.status,c.body FROM investigation_tasks t JOIN cases c ON c.case_id=t.case_id '
                           'WHERE t.task_id=? AND c.tenant=? AND c.app=?',(request['task_id'],context.tenant,context.app)).fetchone()
            if not row:raise PermissionError('task outside authorized domain')
            snapshot,result,case=json.loads(row[0]),json.loads(row[1] or 'null'),json.loads(row[3])
            if row[2]!='success' or not isinstance(result,dict) or digest(result)!=request['result_digest']:raise ValueError('completed unchanged result required')
            if snapshot.get('revision',1)!=case.get('current_revision',1):raise ValueError('current revision required')
            state=_review_state(db,snapshot)
            if state['reviews_digest']!=request['reviews_digest']:raise ValueError('reviews changed')
            if not state['disputed']:raise ValueError('unresolved conflicting reviews required')
            participants={r['reviewer'] for r in state['reviews']}
            participants.update(_investigators(db,snapshot['case_id']))
            if context.principal in participants:raise PermissionError('independent arbiter required')
            body={'arbitration_id':uuid.uuid4().hex,'case_id':snapshot['case_id'],'revision':snapshot.get('revision',1),
                  'tenant_id':context.tenant,'app_id':context.app,'task_id':request['task_id'],
                  'snapshot_id':snapshot['snapshot_id'],'result_digest':request['result_digest'],
                  'reviews_digest':state['reviews_digest'],'reviewer':context.principal,'verdict':request['verdict'],
                  'note':request['note'],'matures_at':maturity,'reviewed_at':time.time(),
                  'label_source':'human_arbitration','disputed':False,'production_action_authorized':False}
            db.execute('INSERT INTO case_arbitrations VALUES(?,?,?,?,?,?,?)',
                       (body['arbitration_id'],body['case_id'],body['revision'],context.principal,request['request_id'],digest(request),json.dumps(body)))
            db.commit();return body
        except BaseException:db.rollback();raise
        finally:db.close()


def export_labels(context,as_of):
    """Export a versioned training input, never overwrite authoritative labels.

    Historical cutoffs cannot see future reviews/arbitrations. Current revision
    selection intentionally excludes superseded evidence, even for older cutoffs.
    """
    context.require('cases.labels.export')
    if type(as_of) not in (int,float) or not math.isfinite(as_of) or not 0<=as_of<=time.time():raise ValueError('past finite cutoff required')
    with data_context(context):
        db=_db(readonly=True)
        try:
            db.execute('BEGIN')
            candidates={};excluded=[];blocked=set()
            for case_id,entity,raw in db.execute('SELECT case_id,entity,body FROM cases WHERE tenant=? AND app=? ORDER BY case_id',
                                               (context.tenant,context.app)):
                case=json.loads(raw)
                state=_review_state(db,{'case_id':case_id,'revision':case.get('current_revision',1)},as_of)
                label=state['effective_label']
                if label is None or not eligible_label(label,as_of):
                    excluded.append({'case_id':case_id,'reason':'disputed' if state['disputed'] else 'unresolved_or_immature'})
                    blocked.add(entity)
                    continue
                candidates.setdefault(entity,[]).append(dict(label,entity_ref=entity,reviews_digest=state['reviews_digest']))
            rows=[]
            for entity,items in sorted(candidates.items()):
                if entity in blocked or len({r['verdict'] for r in items})!=1:
                    excluded.append({'entity_ref':entity,'reason':'conflicting_cases'});continue
                rows.append({'uid':entity,'label':'fraud' if items[0]['verdict']=='confirmed_risk' else 'normal',
                             'source':'reviewed_investigation','provenance':items})
            body={'version':1,'tenant_id':context.tenant,'app_id':context.app,'as_of':as_of,
                  'selection':'current_revisions_mature_uncontested','rows':rows,'excluded':excluded,
                  'gold_holdout_eligible':False}
            return dict(body,dataset_digest=digest(body))
        finally:db.close()


def training_labels(bundle,tenant,app):
    """Explicit opt-in training adapter. These labels are never gold holdout."""
    body={k:v for k,v in bundle.items() if k!='dataset_digest'}
    if bundle.get('dataset_digest')!=digest(body):raise ValueError('label dataset changed')
    if bundle.get('version')!=1 or (bundle.get('tenant_id'),bundle.get('app_id'))!=(tenant,app):raise ValueError('label dataset scope mismatch')
    if bundle.get('gold_holdout_eligible') is not False:raise ValueError('review labels cannot be gold holdout')
    labels={}
    for row in bundle['rows']:
        if row['uid'] in labels or row['label'] not in ('fraud','normal'):raise ValueError('invalid or duplicate label')
        if not row.get('provenance') or any(not eligible_label(r,bundle['as_of']) for r in row['provenance']):raise ValueError('ineligible label')
        if any(r['entity_ref']!=row['uid'] or r['tenant_id']!=tenant or r['app_id']!=app or
               ('fraud' if r['verdict']=='confirmed_risk' else 'normal')!=row['label'] for r in row['provenance']):
            raise ValueError('label provenance mismatch')
        labels[row['uid']]={'label':row['label'],'source':row['source'],'dataset_digest':bundle['dataset_digest']}
    return labels
