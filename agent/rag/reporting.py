"""Citation existence checks, not semantic entailment or verdict validation."""
import re


def citation_audit(summary, retrieved):
    ids = list(dict.fromkeys(re.findall(r'\[K:([^\]\s]+)\]', summary)))
    unknown = [key for key in ids if key not in retrieved]
    return {'status': 'invalid_references' if unknown else 'references_present' if ids else 'no_citations',
            'citations': [retrieved[key] for key in ids if key in retrieved],
            'unknown_chunk_ids': unknown,
            'retrieved_count': len(retrieved),
            'semantic_support_verified': False}
