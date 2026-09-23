#!/usr/bin/env python3
import os
import tempfile
import time

with tempfile.TemporaryDirectory() as tmp:
    os.environ["FK_DATA_DIR"]=tmp
    from agent.event_bus import event_bus

    bus=event_bus()
    event=bus.publish("risk.evidence.accepted","k",{"v":1})
    t=time.time()
    first=bus.claim("risk.evidence.accepted",limit=1,lease_seconds=10,max_attempts=3,now=t)
    assert len(first)==1
    assert first[0].event_id==event.event_id
    assert first[0].attempts==1

    # A concurrent worker cannot claim a live lease.
    second=bus.claim("risk.evidence.accepted",limit=1,lease_seconds=10,max_attempts=3,now=t)
    assert second==[]
    assert bus.acknowledge(event.event_id,"wrong-token") is False

    # After lease expiry, ownership is fenced with a new token.
    reclaimed=bus.claim("risk.evidence.accepted",limit=1,lease_seconds=10,max_attempts=3,now=t+11)
    assert len(reclaimed)==1
    assert reclaimed[0].lease_token!=first[0].lease_token
    assert reclaimed[0].attempts==2
    assert bus.acknowledge(event.event_id,first[0].lease_token) is False
    assert bus.acknowledge(event.event_id,reclaimed[0].lease_token) is True

    poison=bus.publish("risk.evidence.accepted","poison",{"v":2})
    c1=bus.claim("risk.evidence.accepted",limit=1,max_attempts=2,now=t+20)[0]
    assert c1.event_id==poison.event_id
    assert bus.fail(c1.event_id,c1.lease_token,"boom",max_attempts=2)
    c2=bus.claim("risk.evidence.accepted",limit=1,max_attempts=2,now=t+21)[0]
    assert c2.attempts==2
    assert bus.fail(c2.event_id,c2.lease_token,"boom-again",max_attempts=2)
    assert bus.claim("risk.evidence.accepted",limit=1,max_attempts=2,now=t+22)==[]
    dead=bus.dead_letters(topic="risk.evidence.accepted")
    assert len(dead)==1
    assert dead[0]["event"].event_id==poison.event_id
    assert dead[0]["attempts"]==2
print("event bus leasing/dead-letter smoke: PASS")
