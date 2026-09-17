#!/usr/bin/env python3
"""Vendor only the reviewed contract files from an explicit SDK checkout."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

FILES=('report_contract.py','generated_contract.py','business_contract.py',
       'report-upload.schema.json','business-risk-event.schema.json','decision-request.schema.json')

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--sdk',required=True,type=Path)
    parser.add_argument('--check',action='store_true')
    args=parser.parse_args()
    target=Path(__file__).resolve().parents[1]/'agent/contracts'
    mismatches=[]
    digests={}
    for name in FILES:
        raw=(args.sdk/'contracts'/name).read_bytes()
        digests[name]=hashlib.sha256(raw).hexdigest()
        if args.check:
            if not (target/name).exists() or (target/name).read_bytes()!=raw: mismatches.append(name)
        else:
            (target/name).write_bytes(raw)
    if mismatches: raise SystemExit('contract drift: '+', '.join(mismatches))
    print(json.dumps({'files':digests,'mode':'check' if args.check else 'sync'},sort_keys=True))

if __name__=='__main__': main()
