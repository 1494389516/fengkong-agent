#!/usr/bin/env python3
import os
import tempfile
import time

with tempfile.TemporaryDirectory() as tmp:
    os.environ["FK_DATA_DIR"]=tmp
    from agent.graph_store import graph_store
    from agent.graph_training import build_snapshot,attach_point_in_time_labels
    from agent.graph_model_adapter import CallableGNNAdapter

    now=time.time()
    graph_store().append({"evidence_id":"e1","tenant_id":"t","app_id":"a","uid":"u1",
        "device_id":"d","entity_generation":"g","ip":None,
        "observed_at":now-20,"recorded_at":now-10})
    graph_store().append({"evidence_id":"e2","tenant_id":"t","app_id":"a","uid":"u2",
        "device_id":"d","entity_generation":"g","ip":None,
        "observed_at":now-5,"recorded_at":now+10})

    snap=build_snapshot("t","a",now)
    assert len(snap.rows)==1, snap.rows
    bound=attach_point_in_time_labels(
        snap,[{"uid":"u1","label":"fraud","known_at":now-1}])
    assert bound["labels"]=={"u1":"fraud"}

    leaked=False
    try:
        attach_point_in_time_labels(
            snap,[{"uid":"u1","label":"fraud","known_at":now+1}])
    except ValueError as exc:
        leaked="future label leakage" in str(exc)
    assert leaked

    model=CallableGNNAdapter("fake_gnn","1",lambda snapshot,device,generation:{
        "score":0.75,"features":{"nodes":len(snapshot.rows)},
        "explanation":{"reason":"fixture"}})
    out=model.score(snap,"d","g")
    assert out.score==0.75
    assert out.explanation["reason"]=="fixture"
print("graph PIT/model adapter smoke: PASS")
