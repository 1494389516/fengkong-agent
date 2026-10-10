"""Deterministic event assertions. Natural-language claims remain unverified."""
import math
from .evidence_snapshot import digest
from .rag.reporting import valid_assertion


def verify_assertion(assertion, snapshot):
    if not valid_assertion(assertion):
        return {'status':'unverified','reason':'typed_assertion_required'}
    event=snapshot['decision']['event']
    if assertion['subject_ref']!=snapshot['entity_ref']:
        return {'status':'contradicted','reason':'subject_mismatch'}
    window=assertion['time_window']
    if (not isinstance(window,list) or len(window)!=2 or
        any(type(x) not in (int,float) or (type(x) is float and not math.isfinite(x)) for x in window) or
        not window[0]<=event['ts']<window[1] or window[1]>snapshot['as_of']):
        return {'status':'contradicted','reason':'time_window_mismatch'}
    reference=assertion['evidence_ref']; source=None
    if reference=='event:'+event['event_id']: source=event
    for obs in snapshot.get('event_evidence',{}).get('sdk_observations',[]):
        for signal in obs.get('sdk_signal_evidence',{}).get('signals',[]):
            if signal.get('ref')==reference:source=signal
    if source is None:return {'status':'insufficient','reason':'evidence_missing'}
    value=source
    field=assertion['field']
    if not isinstance(field,str) or len(field)>200:return {'status':'unverified','reason':'invalid_field'}
    for key in field.split('.'):
        if not isinstance(value,dict) or key not in value:return {'status':'insufficient','reason':'field_missing'}
        value=value[key]
    if isinstance(value,(dict,list)) or value is None:return {'status':'insufficient','reason':'scalar_observation_required'}
    expected_unit='seconds' if field in ('ts','recorded_at','received_at') else ''
    if assertion['unit']!=expected_unit:return {'status':'contradicted','reason':'unit_mismatch'}
    if assertion['predicate'] not in ('equals','not_equals'):return {'status':'unverified','reason':'unsupported_predicate'}
    expected=assertion['value']
    # bool is not the numeric value 0/1 in a typed assertion.
    equal=type(value)==type(expected) and value==expected
    ok=equal if assertion['predicate']=='equals' else (type(value)==type(expected) and not equal)
    return {'status':'supported' if ok else 'contradicted','reason':'deterministic_observation',
            'evidence_version':digest(source),'verifier_version':'event-assertion-v1',
            'trust':'client_reported' if reference.startswith('sdk:') else 'server_recorded'}


def audit_event_claims(report,snapshot):
    rows=[]
    for index,claim in enumerate((report or {}).get('claims',[])):
        if claim.get('event_evidence'):
            result=verify_assertion(claim.get('assertion'),snapshot)
            assertion=claim.get('assertion')
            if valid_assertion(assertion) and assertion['evidence_ref'] not in claim['event_evidence']:
                result={'status':'unverified','reason':'assertion_reference_not_cited'}
        else:
            result={'status':'not_applicable','reason':'no_event_assertion'}
        rows.append(dict(index=index,**result))
    relevant=[r for r in rows if r['status']!='not_applicable']
    return {'claims':rows,'status':'supported' if relevant and all(r['status']=='supported' for r in relevant) else 'unverified',
            'natural_language_verified':False}


def eligibility(report, event_audit, entailment):
    # Typed facts do not validate arbitrary surrounding prose or authorize actions.
    return {'workflow_status':'completed','evidence_status':event_audit['status'],
            'recommendation_eligibility':'human_review_required',
            'production_action_authorized':False,
            'reasons':['Natural-language interpretation requires review; model output is not an authorization.']}
