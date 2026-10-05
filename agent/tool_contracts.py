"""Tool request contracts and lossless bounded evidence views."""
from dataclasses import dataclass
import json
from jsonschema import Draft202012Validator
from .evidence_snapshot import digest

@dataclass(frozen=True)
class ToolDescriptor:
    name: str
    effect: str
    schema_digest: str
    version: int = 1


def descriptor(name, schema, level):
    from .tool_provenance import ARTIFACT_TOOLS
    effect={'read':'read','simulate':'analysis','propose':'proposal','execute':'state_mutation'}.get(level,'forbidden')
    if name in ARTIFACT_TOOLS:effect='artifact'
    return ToolDescriptor(name,effect,digest(schema))


def validate_arguments(schema, arguments):
    if not isinstance(arguments,dict): raise ValueError('tool arguments must be an object')
    strict = dict(schema, additionalProperties=False)
    Draft202012Validator(strict).validate(arguments)
    # Reject JSON extensions that validators may otherwise treat as numbers.
    json.dumps(arguments,allow_nan=False)


def evidence_view(value):
    """Preserve signal 21+, limitations and all refs; do not silently crop facts."""
    encoded=json.dumps(value,ensure_ascii=False,allow_nan=False)
    if len(encoded.encode())>512*1024:
        raise ValueError('evidence view exceeds byte budget; report evidence_gap')
    from .tools import UGC_KEYS, _wrap_ugc
    def visit(obj, ugc=False):
        if isinstance(obj,dict):return {k:visit(v,ugc or k in UGC_KEYS) for k,v in obj.items()}
        if isinstance(obj,list):return [visit(v,ugc) for v in obj]
        if isinstance(obj,str) and ugc:return _wrap_ugc(obj)
        return obj
    return visit(value)
