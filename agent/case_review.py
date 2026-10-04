"""Authenticated case review, revision-bound and separate from production action."""
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
                    'case':json.loads(case),'result_digest':digest(result)}
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
            db.execute('''CREATE TABLE IF NOT EXISTS case_reviews(
              review_id TEXT PRIMARY KEY, task_id TEXT, principal TEXT, request_id TEXT,
              request_digest TEXT, body TEXT, UNIQUE(principal,request_id))''')
            db.commit();db.execute('BEGIN IMMEDIATE')
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
            if not investigator or investigator==context.principal:raise PermissionError('independent reviewer required')
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
    return (review_record.get('label_source')=='human_review' and not review_record.get('disputed',True)
            and review_record.get('verdict') in ('confirmed_risk','benign')
            and review_record.get('reviewed_at',float('inf'))<=as_of
            and review_record.get('matures_at',float('inf'))<=as_of)


def new_run(context,case_id,revision):
    """Explicit new inference for a pinned revision, never masquerading as replay."""
    context.require('cases.run')
    if type(revision) is not int or revision<1:raise ValueError('invalid revision')
    with data_context(context):
        db=_db()
        try:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT r.body FROM case_revisions r JOIN cases c ON c.case_id=r.case_id '
                'WHERE r.case_id=? AND r.revision=? AND c.tenant=? AND c.app=?',
                (case_id,revision,context.tenant,context.app)).fetchone()
            if not row:raise PermissionError('revision outside authorized domain')
            task_id=uuid.uuid4().hex
            db.execute("INSERT INTO investigation_tasks(task_id,case_id,snapshot,status) VALUES(?,?,?,'queued')",
                       (task_id,case_id,row[0]))
            db.commit();return {'task_id':task_id,'mode':'new_inference','revision':revision}
        except BaseException:db.rollback();raise
        finally:db.close()
