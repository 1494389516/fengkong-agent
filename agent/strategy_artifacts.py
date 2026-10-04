"""Content-bound investigation → candidate → evaluation → release provenance.

Hashes bind content, not reviewer identity. Existing independent controller
roles and release gates remain authoritative even for a well-formed chain.
"""
import copy
from .evidence_snapshot import digest


def build_chain(conclusion, review, mining_body, mining_sha, candidate_id, scope):
    if review.get('result_digest')!=digest(conclusion):raise ValueError('review/result mismatch')
    for key in ('case_id','revision','snapshot_id'):
        if conclusion.get(key)!=review.get(key):raise ValueError('review revision mismatch')
    if review.get('verdict')=='insufficient':raise ValueError('unresolved evidence cannot support a strategy proposal')
    candidates=[c for c in mining_body.get('candidates',[]) if c.get('candidate_id')==candidate_id]
    if len(candidates)!=1:raise ValueError('one existing mined candidate required')
    candidate=candidates[0]
    if not isinstance(candidate.get('ast'),dict) or not isinstance(candidate.get('validation'),dict):
        raise ValueError('structured AST and held-out evaluation required')
    candidate=copy.deepcopy(candidate)
    provenance={'case_id':conclusion['case_id'],'revision':conclusion['revision'],
        'snapshot_id':conclusion['snapshot_id'],'result_digest':digest(conclusion),'review_digest':digest(review)}
    evaluation={'candidate_digest':digest(candidate),'mining_sha256':mining_sha,
                'train':candidate['train'],'validation':candidate['validation'],
                'lineage':{k:v for k,v in mining_body.items() if k.endswith(('fingerprint','digest','version'))},
                'holdout_selection_status':'requires_independent_review'}
    proposal={'scope':scope,'candidate_id':candidate_id,'ast':candidate['ast'],
              'conclusion_digest':digest(provenance),'evaluation_digest':digest(evaluation)}
    chain={'version':1,'conclusion':provenance,'review':copy.deepcopy(review),
           'proposal':proposal,'evaluation':evaluation}
    chain['chain_digest']=digest(chain)
    validate_chain(chain,scope)
    return chain


def validate_chain(chain,scope=None):
    if not isinstance(chain,dict) or set(chain)!={'version','conclusion','review','proposal','evaluation','chain_digest'}:
        raise ValueError('complete investigation artifact chain required')
    body={k:v for k,v in chain.items() if k!='chain_digest'}
    if chain['version']!=1 or digest(body)!=chain['chain_digest']:raise ValueError('artifact chain changed')
    p,c,e,r=(chain[k] for k in ('proposal','conclusion','evaluation','review'))
    if scope is not None and p.get('scope')!=scope:raise ValueError('artifact scope mismatch')
    if p.get('conclusion_digest')!=digest(c) or p.get('evaluation_digest')!=digest(e):raise ValueError('artifact binding mismatch')
    if c.get('review_digest')!=digest(r) or c.get('result_digest')!=r.get('result_digest'):raise ValueError('review binding mismatch')
    if r.get('verdict') not in ('confirmed_risk','benign') or r.get('label_source')!='human_review':raise ValueError('review required')
    if not isinstance(p.get('ast'),dict) or not e.get('mining_sha256'):raise ValueError('evaluated candidate required')
    return copy.deepcopy(chain)


def main():
    import json,os,sys
    from pathlib import Path
    from .tenancy import authenticate,data_context
    from .case_review import detail
    from .investigations import _db
    from .tools.rule_mining import verify_snapshot
    from .tools.shadow_store import artifacts_dir
    from .tools.datasource import agent_state_dir,atomic_write_json
    ctx=authenticate('Bearer '+os.environ.get('FK_PROPOSER_TOKEN',''))
    ctx.require('cases.propose')
    request=json.load(sys.stdin)
    task=detail(ctx,request['task_id'])
    with data_context(ctx):
        db=_db(readonly=True)
        try:
            row=db.execute('SELECT body FROM case_reviews WHERE review_id=? AND task_id=?',
                (request['review_id'],request['task_id'])).fetchone()
            if not row:raise PermissionError('review outside task')
            review=json.loads(row[0])
        finally:db.close()
        path=Path(request['mining_ref']['path']).resolve()
        if artifacts_dir().resolve() not in path.parents:raise PermissionError('artifact outside authorized workspace')
        verified=verify_snapshot(request['mining_ref'])
        if not verified.get('valid'):raise ValueError('invalid mining artifact')
        chain=build_chain(task['result'],review,verified['body'],verified['sha256'],request['candidate_id'],
                          'tenant:'+ctx.tenant+'/app:'+ctx.app)
        path=agent_state_dir()/'strategy_artifacts'/(chain['chain_digest']+'.json')
        atomic_write_json(path,chain)
        print(json.dumps({'path':str(path),'chain_digest':chain['chain_digest'],'release_authorized':False}))

if __name__=='__main__':main()
