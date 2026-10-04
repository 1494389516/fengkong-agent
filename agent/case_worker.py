"""Authenticated, independently scheduled decision-outbox projector."""
import argparse
import json
import os
import time
from .tenancy import authenticate, data_context
from .investigations import consume_decision_outbox, projection_stats


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--once', action='store_true')
    parser.add_argument('--interval', type=float, default=1)
    parser.add_argument('--limit', type=int, default=100)
    args = parser.parse_args()
    if not 0.1 <= args.interval <= 60:
        parser.error('interval must be 0.1..60 seconds')
    while True:
        ctx = authenticate('Bearer ' + os.environ.get('FK_PROJECTOR_TOKEN', ''))
        ctx.require('cases.project')
        with data_context(ctx):
            started = time.monotonic()
            count = consume_decision_outbox(args.limit)
            print(json.dumps({'projected': count, 'backlog':projection_stats(), 'elapsed_ms': 1000*(time.monotonic()-started),
                              'updated_at': time.time()}), flush=True)
        if args.once:
            return
        time.sleep(args.interval)


if __name__ == '__main__':
    main()
