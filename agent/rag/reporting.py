"""Structural grounding checks, not semantic entailment or verdict validation."""
import json
import re


def citation_audit(summary, retrieved):
    ids = list(dict.fromkeys(re.findall(r'\[K:([^\]\s]+)\]', summary)))
    unknown = [key for key in ids if key not in retrieved]
    return {'status': 'invalid_references' if unknown else 'references_present' if ids else 'no_citations',
            'citations': [retrieved[key] for key in ids if key in retrieved],
            'unknown_chunk_ids': unknown,
            'retrieved_count': len(retrieved),
            'semantic_support_verified': False}


VERDICTS = frozenset(('evidence_gap', 'needs_review', 'risk_supported',
                      'benign_explanation_supported'))
ROLES = frozenset(('finding', 'counterevidence', 'limitation'))
CONFIDENCE = frozenset(('low', 'medium', 'high'))


def parse_investigation_report(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 50000:
        return None, ['report must be a bounded JSON object']
    text = value.strip()
    if text.startswith('```') and text.endswith('```'):
        lines = text.splitlines()
        text = '\n'.join(lines[1:-1]).strip()
    try:
        report = json.loads(text)
    except (TypeError, ValueError):
        return None, ['report is not valid JSON']
    errors = []
    required = {'verdict', 'claims', 'missing_evidence', 'recommended_next_step'}
    if not isinstance(report, dict) or set(report) != required:
        return None, ['report fields must be exactly ' + ','.join(sorted(required))]
    if report.get('verdict') not in VERDICTS:
        errors.append('invalid verdict')
    if (not isinstance(report.get('claims'), list) or len(report['claims']) > 20):
        errors.append('claims must be a list of at most 20 items')
    if (not isinstance(report.get('missing_evidence'), list)
            or len(report['missing_evidence']) > 20
            or any(not isinstance(item, str) or not item.strip() or len(item) > 500
                   for item in report['missing_evidence'])):
        errors.append('invalid missing_evidence')
    if (not isinstance(report.get('recommended_next_step'), str)
            or not report['recommended_next_step'].strip()
            or len(report['recommended_next_step']) > 1000):
        errors.append('invalid recommended_next_step')
    for index, claim in enumerate(report.get('claims', []) if isinstance(report.get('claims'), list) else []):
        fields = {'statement', 'role', 'event_evidence', 'knowledge_citations', 'confidence'}
        if not isinstance(claim, dict) or set(claim) != fields:
            errors.append('claim %d has invalid fields' % index)
            continue
        if (not isinstance(claim['statement'], str) or not claim['statement'].strip()
                or len(claim['statement']) > 2000):
            errors.append('claim %d has invalid statement' % index)
        if claim['role'] not in ROLES:
            errors.append('claim %d has invalid role' % index)
        if claim['confidence'] not in CONFIDENCE:
            errors.append('claim %d has invalid confidence' % index)
        for name in ('event_evidence', 'knowledge_citations'):
            values = claim[name]
            if (not isinstance(values, list) or len(values) > 20
                    or any(not isinstance(item, str) or not item or len(item) > 300 for item in values)):
                errors.append('claim %d has invalid %s' % (index, name))
    return (report if not errors else None), errors


def claim_evidence_audit(summary, retrieved, event_registry, retrieval):
    report, errors = parse_investigation_report(summary)
    result = {'status': 'invalid_report' if errors else 'structurally_grounded',
              'schema_errors': errors, 'claim_count': 0, 'claims': [],
              'unknown_event_refs': [], 'unknown_knowledge_refs': [],
              'malformed_knowledge_citations': [], 'misaligned_knowledge_refs': [],
              'unsupported_claim_indexes': [], 'workflow_issues': [],
              'semantic_support_verified': False}
    if report is None:
        return None, result
    result['claim_count'] = len(report['claims'])
    unknown_events, unknown_knowledge = set(), set()
    malformed_citations, misaligned_knowledge, unsupported = set(), set(), []
    has_counterclaim = False
    has_event_finding = False
    for index, claim in enumerate(report['claims']):
        event_refs = list(dict.fromkeys(claim['event_evidence']))
        knowledge_refs, malformed = [], []
        for citation in claim['knowledge_citations']:
            match = re.fullmatch(r'\[K:([^\]\s]+)\]', citation)
            if match:
                knowledge_refs.append(match.group(1))
            else:
                malformed.append(citation)
        bad_events = [ref for ref in event_refs if ref not in event_registry]
        bad_knowledge = [ref for ref in knowledge_refs if ref not in retrieved]
        known_events = [ref for ref in event_refs if ref in event_registry]
        known_knowledge = [ref for ref in knowledge_refs if ref in retrieved]
        misaligned = [ref for ref in known_knowledge
                      if claim['role'] == 'counterevidence'
                      and 'counterevidence' not in retrieved[ref].get('retrieval_purposes', [])]
        aligned_knowledge = [ref for ref in known_knowledge if ref not in misaligned]
        required_evidence = (bool(known_events) if claim['role'] == 'finding' else
                             bool(known_events or aligned_knowledge)
                             if claim['role'] == 'counterevidence' else True)
        structurally_supported = (not bad_events and not bad_knowledge and not malformed
                                  and not misaligned and required_evidence)
        if claim['role'] in ('finding', 'counterevidence') and not structurally_supported:
            unsupported.append(index)
        if claim['role'] == 'finding' and structurally_supported:
            has_event_finding = True
        if claim['role'] == 'counterevidence':
            has_counterclaim = True
        unknown_events.update(bad_events); unknown_knowledge.update(bad_knowledge)
        malformed_citations.update(malformed); misaligned_knowledge.update(misaligned)
        result['claims'].append({'index': index, 'role': claim['role'],
            'known_event_refs': known_events, 'known_knowledge_refs': known_knowledge,
            'unknown_event_refs': bad_events, 'unknown_knowledge_refs': bad_knowledge,
            'malformed_knowledge_citations': malformed,
            'misaligned_knowledge_refs': misaligned,
            'structurally_supported': structurally_supported})
    if not has_event_finding:
        result['workflow_issues'].append('event-grounded finding missing')
    if not has_counterclaim:
        result['workflow_issues'].append('counterevidence claim missing')
    if retrieved and retrieval.get('outcome') == 'counterevidence_not_checked':
        result['workflow_issues'].append('knowledge used without counterevidence search')
    result['unknown_event_refs'] = sorted(unknown_events)
    result['unknown_knowledge_refs'] = sorted(unknown_knowledge)
    result['malformed_knowledge_citations'] = sorted(malformed_citations)
    result['misaligned_knowledge_refs'] = sorted(misaligned_knowledge)
    result['unsupported_claim_indexes'] = sorted(set(unsupported))
    if (unknown_events or unknown_knowledge or malformed_citations
            or misaligned_knowledge or unsupported):
        result['status'] = 'unsupported_claims'
    elif result['workflow_issues']:
        result['status'] = 'workflow_incomplete'
    return report, result
