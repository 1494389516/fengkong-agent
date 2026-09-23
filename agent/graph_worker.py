"""Drain accepted-evidence events into bounded graph projections."""
import argparse
import json
import time

from .graph_risk import consume_pending
from .event_bus import event_bus
from .graph_worker_health import write_heartbeat


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--once",action="store_true")
    p.add_argument("--interval",type=float,default=1.0)
    p.add_argument("--limit",type=int,default=100)
    args=p.parse_args()
    while True:
        result=consume_pending(limit=args.limit)
        stats=event_bus().stats(topic="risk.evidence.accepted")
        heartbeat=write_heartbeat(result,stats)
        print(json.dumps({**result,"bus":stats,"heartbeat":heartbeat["updated_at"]},
                         ensure_ascii=False),flush=True)
        if args.once:return
        time.sleep(max(0.1,args.interval))


if __name__=="__main__":
    main()
