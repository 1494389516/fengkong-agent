"""Explicit authenticated worker entrypoint. Runs one queued task per invocation."""
import argparse
import json
import os
from .tenancy import authenticate
from .investigations import run_task
from .case_review import new_run


def main():
    p=argparse.ArgumentParser(description=__doc__)
    group=p.add_mutually_exclusive_group(required=True)
    group.add_argument('--task-id')
    group.add_argument('--new-run-case')
    p.add_argument('--revision',type=int)
    args=p.parse_args()
    ctx=authenticate('Bearer '+os.environ.get('FK_INVESTIGATOR_TOKEN',''))
    if args.new_run_case:
        result=new_run(ctx,args.new_run_case,args.revision)
    else:result=run_task(args.task_id,ctx)
    print(json.dumps(result,ensure_ascii=False,allow_nan=False))
if __name__=='__main__':main()
