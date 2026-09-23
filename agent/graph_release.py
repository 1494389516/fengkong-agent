"""Graph model release-readiness bridge.

This module never activates a model. It converts a challenger with immutable
artifact/evaluation lineage into a Control-Plane-ready component only when the
declared runtime loader is actually supported.
"""
import copy
import hashlib
import json

from . import graph_model_registry as registry


def _digest(value):
    blob=json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False,
                    allow_nan=False).encode()
    return hashlib.sha256(blob).hexdigest()


def _find(name,version):
    rows=registry.status(name)
    return next((r for r in rows if r["version"]==version),None)


def release_readiness(name,version):
    row=_find(name,version)
    reasons=[]
    if row is None:
        return {"ready":False,"reasons":["graph model not registered"]}
    if row.get("status")!="challenger":
        reasons.append("graph model must be challenger")
    evaluations=row.get("evaluations") or []
    latest=evaluations[-1] if evaluations else None
    if latest is None:
        reasons.append("recorded evaluation required")
    elif int((latest.get("metrics") or {}).get("sample_count") or 0)<=0:
        reasons.append("nonempty evaluation sample required")

    runtime=copy.deepcopy(row.get("runtime_contract") or {})
    loader=runtime.get("loader")
    if loader!="builtin_graph_algorithm_v1":
        reasons.append("runtime loader is not production-supported")
    else:
        algorithm=runtime.get("algorithm")
        try:
            from .graph_algorithms import graph_algorithm
            graph_algorithm(algorithm)
        except Exception:
            reasons.append("declared graph algorithm is unavailable")

    candidate={
        "name":row.get("name"),"version":row.get("version"),
        "adapter_kind":row.get("adapter_kind"),
        "artifact_digest":row.get("artifact_digest"),
        "train_snapshot_fingerprint":row.get("train_snapshot_fingerprint"),
        "runtime_contract":runtime,
        "evaluation":copy.deepcopy(latest),
    }
    candidate["candidate_digest"]=_digest(candidate)
    return {"ready":not reasons,"reasons":reasons,"candidate":candidate}


def build_control_plane_component(name,version):
    readiness=release_readiness(name,version)
    if not readiness["ready"]:
        raise RuntimeError("graph release not ready: "+"; ".join(readiness["reasons"]))
    candidate=readiness["candidate"]
    evaluation=candidate["evaluation"]
    metrics=evaluation.get("metrics") or {}
    evidence={
      "snapshot_fingerprint":evaluation.get("snapshot_fingerprint"),
      "label_binding_fingerprint":evaluation.get("label_binding_fingerprint"),
      "account_aggregation":evaluation.get("account_aggregation"),
      "sample_count":metrics.get("sample_count"),
      "metrics_digest":_digest(metrics),
    }
    component={
      "kind":"graph_model_v1",
      "name":candidate["name"],"version":candidate["version"],
      "artifact_digest":candidate["artifact_digest"],
      "runtime_contract":candidate["runtime_contract"],
      "train_snapshot_fingerprint":candidate["train_snapshot_fingerprint"],
      "evaluation_evidence":evidence,
      "candidate_digest":candidate["candidate_digest"],
    }
    component["component_digest"]=_digest(component)
    return component
