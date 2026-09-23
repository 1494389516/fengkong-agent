#!/usr/bin/env python3
import os
import tempfile
import time

with tempfile.TemporaryDirectory() as tmp:
    os.environ["FK_DATA_DIR"]=tmp
    from agent.graph_store import graph_store
    from agent.graph_training import build_snapshot,attach_point_in_time_labels
    from agent.graph_model_adapter import CallableGNNAdapter
    from agent.graph_model_eval import evaluate_graph_model
    from agent import graph_model_registry as registry

    now=time.time()
    for eid,uid,device in (("e1","fraud_uid","df"),("e2","normal_uid","dn")):
        graph_store().append({"evidence_id":eid,"tenant_id":"t","app_id":"a","uid":uid,
            "device_id":device,"entity_generation":"g","ip":None,
            "observed_at":now-2,"recorded_at":now-1})
    snap=build_snapshot("t","a",now)
    labels=attach_point_in_time_labels(snap,[
        {"uid":"fraud_uid","label":"fraud","known_at":now-0.5},
        {"uid":"normal_uid","label":"normal","known_at":now-0.5},
    ])
    model=CallableGNNAdapter("graph_gnn","1",lambda snapshot,device,generation:{
        "score":0.9 if device=="df" else 0.1,
        "features":{"device":device},"explanation":{"source":"fixture"}})
    result=evaluate_graph_model(model,snap,labels)
    assert result["metrics"]["auc"]==1.0,result
    assert result["metrics"]["sample_count"]==2
    row=registry.register("graph_gnn","1",snap.fingerprint,"callable_gnn","a"*64,
        runtime_contract={"loader":"offline_only"})
    assert row["status"]=="candidate"
    registry.record_evaluation("graph_gnn","1",result)
    assert registry.promote("graph_gnn","1","shadow")["status"]=="shadow"
    assert registry.promote("graph_gnn","1","challenger")["status"]=="challenger"
    blocked=False
    try:
        registry.promote("graph_gnn","1","champion")
    except PermissionError:
        blocked=True
    assert blocked
    from agent.graph_release import release_readiness
    readiness=release_readiness("graph_gnn","1")
    assert readiness["ready"] is False
    assert "runtime loader is not production-supported" in readiness["reasons"]
print("graph model eval/registry smoke: PASS")
