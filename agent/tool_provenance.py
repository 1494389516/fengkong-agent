"""Server-owned field dependencies; model-supplied trust labels confer nothing."""
from contextlib import contextmanager
from contextvars import ContextVar
import math
import os
import threading
import time
from .evidence_snapshot import digest

# Only these implementations write regenerable artifacts to isolated Agent state.
ARTIFACT_TOOLS=frozenset({'chart_account_timeline','chart_threshold_sweep',
                          'chart_cohort_features','chart_drift_dashboard'})
_binding=ContextVar('verified_argument_dependencies',default=None)
_render_lock=threading.RLock()


@contextmanager
def artifact_lock():
    from .tools.datasource import agent_state_dir,file_lock
    with _render_lock,file_lock(agent_state_dir()/'.artifact_write'):
        yield


def leaves(value,path=''):
    if isinstance(value,dict):
        for key,item in value.items():
            yield from leaves(item,path+'/'+key.replace('~','~0').replace('/','~1'))
    elif isinstance(value,list):
        for index,item in enumerate(value):yield from leaves(item,path+'/'+str(index))
    else:yield path,value


def record(tool,arguments,result,state,scope,trust):
    """Keep bounded hashes, never promote UGC/error fields into authority."""
    from .tools import UGC_KEYS
    if not isinstance(result,dict) or 'error' in result:return
    binding=dict(run_id=state['run_id'],tool=tool,args_digest=digest(arguments),
                 result_digest=digest(result),scope=scope)
    ref=digest(binding)
    fields={}
    for path,value in leaves(result):
        if len(fields)>=512:break
        components=[s.replace('~1','/').replace('~0','~') for s in path.split('/')[1:]]
        field_trust='user_provided' if any(k in UGC_KEYS for k in components) else trust or 'unknown'
        fields[path]={'digest':digest(value),'trust':field_trust}
    records=state.setdefault('evidence',{})
    # A reference must remain in the current bounded trajectory to authorize.
    if len(records)>=16 and ref not in records:del records[next(iter(records))]
    records[ref]=dict(binding,fields=fields)
    return ref


def _scope():
    from .governance import _scope_fields
    return _scope_fields()


@contextmanager
def authorize_arguments(context,tool,arguments,bindings,*,expires_at):
    """Host-only entrypoint; never registered as an Agent tool.

    Operator credential, scoped tool permission and every argument's exact
    evidence field must agree. This may authorize a regenerable artifact after
    RAG; it can never bypass policy for a production mutation.
    """
    from .governance import trajectory_snapshot
    from .tools.capability import get_scope
    context.require('artifacts.create')
    if not os.environ.get('FK_AGENT_STATE_ROOT'):raise PermissionError('isolated artifact store required')
    from .tools.datasource import agent_state_dir
    artifact_root=str(agent_state_dir())
    scope=get_scope()
    if tool not in ARTIFACT_TOOLS or scope is None or not scope.permits(tool):raise PermissionError('artifact tool scope required')
    if (scope.principal,scope.tenant,scope.dataset)!=(context.principal,context.tenant,context.dataset):raise PermissionError('argument authority scope mismatch')
    if type(expires_at) not in (int,float) or not math.isfinite(expires_at) or not time.time()<expires_at<=min(scope.expires_at,context.expires_at):raise PermissionError('argument authority expiry invalid')
    state=trajectory_snapshot()
    if not isinstance(bindings,dict) or set(bindings)!=set(dict(leaves(arguments))):raise PermissionError('every argument leaf needs an evidence dependency')
    for path,value in leaves(arguments):
        source=bindings[path]
        if not isinstance(source,dict) or set(source)!={'ref','path'}:raise PermissionError('invalid argument dependency')
        record=state.get('evidence',{}).get(source['ref'],{})
        field=record.get('fields',{}).get(source['path'],{})
        if record.get('run_id')!=state['run_id'] or record.get('scope')!=_scope():raise PermissionError('evidence outside current run or scope')
        if field.get('trust')!='server_evidence' or field.get('digest')!=digest(value):raise PermissionError('untrusted or changed argument dependency')
    sources={b['ref']:state['evidence'][b['ref']] for b in bindings.values()}
    grant=dict(tool=tool,artifact_root=artifact_root,args_digest=digest(arguments),dependencies_digest=digest(bindings),
               source_refs=list(sources),evidence_digest=digest(sources),
               run_id=state['run_id'],scope=_scope(),expires_at=expires_at)
    token=_binding.set(grant)
    try:yield grant
    finally:_binding.reset(token)


def verified_binding(tool,arguments):
    from .governance import trajectory_snapshot
    grant=_binding.get()
    if (not grant or grant['tool']!=tool or grant['args_digest']!=digest(arguments)
            or grant['run_id']!=trajectory_snapshot()['run_id'] or grant['scope']!=_scope()
            or grant['expires_at']<=time.time()):return None
    from .tools.datasource import agent_state_dir
    if not os.environ.get('FK_AGENT_STATE_ROOT') or str(agent_state_dir())!=grant['artifact_root']:return None
    records=trajectory_snapshot().get('evidence',{})
    if digest({ref:records.get(ref) for ref in grant['source_refs']})!=grant['evidence_digest']:return None
    return dict(grant)


def dispatch_authorized_artifact(context,tool,arguments,bindings,*,expires_at):
    """Authenticated host call; ordinary dispatch cannot invent this authority."""
    from .tools import dispatch
    with authorize_arguments(context,tool,arguments,bindings,expires_at=expires_at):
        return dispatch(tool,arguments)
