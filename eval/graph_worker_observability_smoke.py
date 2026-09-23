#!/usr/bin/env python3
import os
import tempfile
import time

with tempfile.TemporaryDirectory() as tmp:
    os.environ["FK_DATA_DIR"]=tmp
    from agent.event_bus import event_bus
    from agent.graph_worker_health import write_heartbeat,read_health

    bus=event_bus()
    t=time.time()
    bus.publish("risk.evidence.accepted","k",{"v":1})
    aged=bus.stats(topic="risk.evidence.accepted",now=t+120)
    assert aged["pending"]==1 and aged["ready"]==1
    assert aged["oldest_pending_age_seconds"]>=119
    write_heartbeat({"processed":0,"failed":[]},aged,now=t+120)
    health=read_health(now=t+121,max_backlog_age_seconds=60)
    assert health["level"]=="degraded"
    assert "backlog_old" in health["reason"]

    claim=bus.claim("risk.evidence.accepted",limit=1,now=t+120)[0]
    assert bus.acknowledge(claim.event_id,claim.lease_token)
    clean=bus.stats(topic="risk.evidence.accepted",now=t+121)
    assert clean["pending"]==0 and clean["dead_letters"]==0
    write_heartbeat({"processed":1,"failed":[]},clean,now=t+121)
    assert read_health(now=t+122)["level"]=="ok"

    stale=read_health(now=t+140,max_age_seconds=10)
    assert stale["level"]=="degraded"
    assert "heartbeat_stale" in stale["reason"]

    dead_stats={**clean,"dead_letters":1}
    write_heartbeat({"processed":0,"failed":[]},dead_stats,now=t+141)
    dead=read_health(now=t+142)
    assert dead["level"]=="degraded"
    assert "dead_letters_present" in dead["reason"]
print("graph worker observability smoke: PASS")
