#!/usr/bin/env python3
import os
import tempfile
import time

with tempfile.TemporaryDirectory() as tmp:
    os.environ["FK_DATA_DIR"]=tmp
    from agent.event_bus import event_bus
    from agent.graph_risk import consume_pending, lookup

    now=time.time()
    base={"tenant_id":"t","app_id":"a","identity_trust":"server_bound",
          "device_id":"dev","entity_generation":"g1","observed_at":now,"recorded_at":now}
    for i,uid in enumerate(("u1","u2","u3")):
        obs={**base,"evidence_id":f"e{i}","uid":uid,"ip":"203.0.113.1"}
        event_bus().publish("risk.evidence.accepted",obs["evidence_id"],obs)
    # An unrelated event must not starve or be acknowledged by the graph consumer.
    event_bus().publish("other.topic","x",{"x":1})
    result=consume_pending(limit=10)
    assert result["processed"]==3 and not result["failed"],result
    graph=lookup("t","a","dev","g1")
    assert graph is not None
    assert graph["algorithm"]=="community_v1"
    assert graph["account_count"]==3
    assert graph["shared_account_count"]==2
    assert graph["interpretation"]=="association_features_only"
    pending=event_bus().pending(limit=10)
    assert len(pending)==1 and pending[0].topic=="other.topic"
    assert os.path.exists(os.path.join(tmp,"online.sqlite3"))
    assert os.path.exists(os.path.join(tmp,"graph.sqlite3"))
    assert os.path.exists(os.path.join(tmp,"features.sqlite3"))
print("graph pipeline smoke: PASS")
