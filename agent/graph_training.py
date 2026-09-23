"""Immutable point-in-time graph dataset snapshots for offline model research.

Snapshots are bounded by server knowledge time (recorded_at), not event time.
Labels are optional and accepted only when their known_at <= the same cutoff.
"""
import hashlib
import json
import math
from dataclasses import dataclass

from .graph_store import graph_store


@dataclass(frozen=True)
class GraphSnapshot:
    tenant: str
    app: str
    knowledge_cutoff: float
    rows: tuple
    truncated: bool
    fingerprint: str

    def as_dict(self):
        return {
            "tenant":self.tenant,"app":self.app,
            "knowledge_cutoff":self.knowledge_cutoff,
            "rows":[list(r) for r in self.rows],
            "truncated":self.truncated,"fingerprint":self.fingerprint,
        }


def _fingerprint(payload):
    blob=json.dumps(payload,sort_keys=True,separators=(",",":"),ensure_ascii=False,
                    allow_nan=False).encode()
    return hashlib.sha256(blob).hexdigest()


def build_snapshot(tenant,app,knowledge_cutoff,*,limit=5000):
    if not isinstance(tenant,str) or not tenant or not isinstance(app,str) or not app:
        raise ValueError("tenant/app required")
    if type(knowledge_cutoff) not in (int,float) or not math.isfinite(knowledge_cutoff):
        raise ValueError("finite knowledge cutoff required")
    if type(limit) is not int or not 1<=limit<=50000:
        raise ValueError("snapshot limit must be 1..50000")
    rows,truncated=graph_store().scope_rows(tenant,app,float(knowledge_cutoff),limit=limit)
    frozen=tuple(tuple(r) for r in rows)
    payload={"tenant":tenant,"app":app,"knowledge_cutoff":float(knowledge_cutoff),
             "rows":[list(r) for r in frozen],"truncated":bool(truncated)}
    return GraphSnapshot(tenant,app,float(knowledge_cutoff),frozen,bool(truncated),
                         _fingerprint(payload))


def attach_point_in_time_labels(snapshot,label_records):
    """Bind labels with explicit knowledge timestamps; future labels are rejected."""
    if not isinstance(snapshot,GraphSnapshot):
        raise TypeError("GraphSnapshot required")
    if not isinstance(label_records,list):
        raise ValueError("label_records must be a list")
    labels={}
    provenance=[]
    for row in label_records:
        if not isinstance(row,dict):
            raise ValueError("label record must be object")
        uid=row.get("uid");label=row.get("label");known_at=row.get("known_at")
        if not isinstance(uid,str) or not uid or label not in ("fraud","normal"):
            raise ValueError("valid uid/fraud|normal label required")
        if type(known_at) not in (int,float) or not math.isfinite(known_at):
            raise ValueError("label known_at required for PIT evaluation")
        if known_at>snapshot.knowledge_cutoff:
            raise ValueError("future label leakage")
        if uid in labels and labels[uid] != label:
            raise ValueError("conflicting label history requires an explicit as-of resolver")
        labels[uid]=label
        provenance.append((uid,label,float(known_at)))
    binding={"snapshot_fingerprint":snapshot.fingerprint,
             "knowledge_cutoff":snapshot.knowledge_cutoff,
             "labels":labels,"label_provenance":sorted(provenance)}
    binding["fingerprint"]=_fingerprint(binding)
    return binding


def temporal_split(train_cutoff,eval_cutoff):
    if type(train_cutoff) not in (int,float) or type(eval_cutoff) not in (int,float):
        raise ValueError("finite cutoffs required")
    if not math.isfinite(train_cutoff) or not math.isfinite(eval_cutoff) or eval_cutoff<=train_cutoff:
        raise ValueError("eval cutoff must be later than train cutoff")
    return {"train_cutoff":float(train_cutoff),"eval_cutoff":float(eval_cutoff),
            "ordered_knowledge_cutoffs":True,
            "evaluation_state_includes_prior_history":True}
