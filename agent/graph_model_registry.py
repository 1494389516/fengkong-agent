"""Metadata registry for graph model experiments.

This registry cannot activate production models. It records candidate/shadow/
challenger evidence only; production activation remains Control Plane + signed release.
"""
import copy
import json
import time
from .tools.datasource import data_dir,atomic_write_json

PATH="graph_model_registry.json"
_ALLOWED={"candidate":"shadow","shadow":"challenger"}


def _path():
    return data_dir()/PATH


def _load():
    p=_path()
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else []


def _save(rows):
    atomic_write_json(_path(),rows)


def register(name,version,train_snapshot_fingerprint,adapter_kind,artifact_digest,note=""):
    if not all(isinstance(x,str) and x.strip() for x in
               (name,version,train_snapshot_fingerprint,adapter_kind,artifact_digest)):
        raise ValueError("complete graph model identity required")
    if len(artifact_digest)!=64 or any(ch not in "0123456789abcdef" for ch in artifact_digest.lower()):
        raise ValueError("artifact_digest must be sha256 hex")
    rows=_load()
    if any(r["name"]==name and r["version"]==version for r in rows):
        raise ValueError("graph model already registered")
    row={"name":name,"version":version,"adapter_kind":adapter_kind,
         "artifact_digest":artifact_digest.lower(),
         "train_snapshot_fingerprint":train_snapshot_fingerprint,
         "status":"candidate","created_at":time.time(),"note":note,
         "evaluations":[]}
    rows.append(row);_save(rows);return copy.deepcopy(row)


def record_evaluation(name,version,result):
    rows=_load()
    row=next((r for r in rows if r["name"]==name and r["version"]==version),None)
    if row is None: raise ValueError("graph model not registered")
    if result.get("model_name")!=name or result.get("model_version")!=version:
        raise ValueError("evaluation model identity mismatch")
    item={
      "snapshot_fingerprint":result.get("snapshot_fingerprint"),
      "label_binding_fingerprint":result.get("label_binding_fingerprint"),
      "account_aggregation":result.get("account_aggregation"),
      "metrics":copy.deepcopy(result.get("metrics") or {}),
      "recorded_at":time.time(),
    }
    if not item["snapshot_fingerprint"] or not item["label_binding_fingerprint"]:
        raise ValueError("complete evaluation lineage required")
    row["evaluations"].append(item);_save(rows);return copy.deepcopy(item)


def promote(name,version,target):
    if target=="champion":
        raise PermissionError("graph model champion activation requires signed Control Plane release")
    rows=_load();row=next((r for r in rows if r["name"]==name and r["version"]==version),None)
    if row is None: raise ValueError("graph model not registered")
    if _ALLOWED.get(row["status"])!=target:
        raise ValueError("illegal graph model transition")
    if target=="challenger" and not row.get("evaluations"):
        raise ValueError("challenger requires recorded evaluation")
    row["status"]=target;row["promoted_at"]=time.time();_save(rows)
    return copy.deepcopy(row)


def status(name=None):
    rows=_load()
    return [copy.deepcopy(r) for r in rows if name is None or r["name"]==name]
