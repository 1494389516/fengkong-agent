"""Offline evaluation for graph model adapters.

Account-level evaluation is explicit: each account receives the maximum score of
its connected device generations in the immutable PIT snapshot. The aggregation
rule is recorded so comparisons remain reproducible.
"""
from .metrics import evaluate, compare, promotion_significance
from .graph_model_adapter import GraphModelAdapter
from .graph_training import GraphSnapshot


def evaluate_graph_model(adapter,snapshot,label_binding,*,account_aggregation="max"):
    if not isinstance(adapter,GraphModelAdapter):
        raise TypeError("GraphModelAdapter required")
    if not isinstance(snapshot,GraphSnapshot):
        raise TypeError("GraphSnapshot required")
    if account_aggregation!="max":
        raise ValueError("only explicit max aggregation is currently supported")
    if label_binding.get("snapshot_fingerprint")!=snapshot.fingerprint:
        raise ValueError("label binding belongs to another graph snapshot")

    device_to_accounts={}
    for _,uid,device,generation,ip,observed_at,recorded_at in snapshot.rows:
        if uid:
            device_to_accounts.setdefault((device,generation),set()).add(uid)

    device_scores={}
    account_scores={}
    explanations={}
    for device,generation in sorted(device_to_accounts):
        out=adapter.score(snapshot,device,generation)
        device_scores[f"{device}:{generation}"]=out.score
        explanations[f"{device}:{generation}"]=out.explanation
        for uid in device_to_accounts[(device,generation)]:
            if uid not in account_scores or out.score>account_scores[uid]:
                account_scores[uid]=out.score

    labels=dict(label_binding.get("labels") or {})
    metrics=evaluate(account_scores,labels)
    metrics.update(
        graph_snapshot_fingerprint=snapshot.fingerprint,
        label_binding_fingerprint=label_binding.get("fingerprint"),
        model_name=adapter.model_name,
        model_version=adapter.model_version,
        account_aggregation=account_aggregation,
        device_score_count=len(device_scores),
        account_score_count=len(account_scores),
    )
    return {
        "model_name":adapter.model_name,
        "model_version":adapter.model_version,
        "snapshot_fingerprint":snapshot.fingerprint,
        "label_binding_fingerprint":label_binding.get("fingerprint"),
        "account_aggregation":account_aggregation,
        "metrics":metrics,
        "account_scores":account_scores,
        "device_scores":device_scores,
        "explanations":explanations,
    }


def compare_graph_model_results(champion,challenger,labels):
    for key in ("snapshot_fingerprint","label_binding_fingerprint","account_aggregation"):
        if champion.get(key)!=challenger.get(key):
            raise ValueError("graph model comparison requires identical "+key)
    table=compare(champion["metrics"],challenger["metrics"])
    gate=promotion_significance(
        champion["metrics"],challenger["metrics"],
        champion.get("account_scores") or {},challenger.get("account_scores") or {},
        labels or {},
    )
    return {"comparison":table,"promotion_gate":gate}
