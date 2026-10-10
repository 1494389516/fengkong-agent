"""Server-owned bounded DAG; domain roles are restricted tool subflows."""
from .evidence_snapshot import digest

ROLE_TOOLS={
    'device_evidence':frozenset({'get_event_evidence'}),
    'graph_behavior':frozenset({'graph_relations'}),
    'business_facts':frozenset({'feature_stats','rule_eval'}),
    'counterevidence':frozenset({'search_risk_knowledge'}),
}
VERSION='investigation-plan-v2'


def template(snapshot, granted):
    event=snapshot['decision']['event']
    nodes=[dict(id='evidence',role='device_evidence',tool='get_event_evidence',
                args={'event_id':snapshot['decision'].get('business_event_id') or event['event_id']},depends=[])]
    # Only the prerequisite evidence is eager. Graph/business reads are selected
    # by the investigator when needed, under the same scope and resource budget.
    # Counterevidence queries need a concrete phenomenon, so they remain a bounded
    # generator branch enforced by the existing retrieval contract (max 3).
    return {'version':VERSION,'nodes':nodes,'counterevidence':'bounded_retrieval_branch'}


def validate(plan, snapshot, granted):
    if plan.get('version')!=VERSION:raise ValueError('unsupported plan version')
    nodes=plan.get('nodes')
    if not isinstance(nodes,list) or not 1<=len(nodes)<=min(8,snapshot['budget']['max_tool_calls']):
        raise ValueError('plan node budget exceeded')
    ids=set();ordered=[];remaining=list(nodes)
    for node in nodes:
        if set(node)!={'id','role','tool','args','depends'}:raise ValueError('invalid plan node')
        if not isinstance(node['id'],str) or node['id'] in ids:raise ValueError('duplicate node')
        ids.add(node['id'])
        allowed=set(granted)&set(snapshot['allowed_tools'])&ROLE_TOOLS.get(node['role'],frozenset())
        if node['tool'] not in allowed:raise PermissionError('plan role/tool intersection denied')
        if not isinstance(node['depends'],list) or not isinstance(node['args'],dict):raise ValueError('invalid plan types')
        if node['args'].get('uid',snapshot['entity_ref'])!=snapshot['entity_ref']:raise PermissionError('plan entity mismatch')
    complete=set()
    while remaining:
        ready=[node for node in remaining if set(node['depends'])<=complete]
        if not ready:raise ValueError('plan cycle or missing dependency')
        for node in ready:
            ordered.append(node);complete.add(node['id']);remaining.remove(node)
    return ordered


def execute(plan,snapshot,granted,ledger,state):
    from .tools import dispatch
    from . import governance
    outputs={}
    for node in validate(plan,snapshot,granted):
        key='plan:'+node['id']
        cached=ledger.begin(key,'read_tool',dict(node,plan_version=plan['version']))
        if cached is None:
            output=dispatch(node['tool'],node['args'])
            cached={'output':output,'state':{k:v for k,v in state.items() if k!='snapshot'},
                    'trajectory':governance.trajectory_snapshot()}
            ledger.complete(key,cached)
        else:
            state.update(cached['state']);governance.restore_trajectory(cached['trajectory'])
        outputs[node['id']]=cached['output']
    return {'plan_digest':digest(plan),'outputs':outputs,
            'status':'evidence_gap' if any(isinstance(v,dict) and 'error' in v for v in outputs.values()) else 'collected'}
