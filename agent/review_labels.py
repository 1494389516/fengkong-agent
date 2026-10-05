"""Export authenticated mature review labels to a content-addressed training input."""
import argparse
import json
import os
import time
from .tenancy import authenticate, data_context
from .case_review import export_labels, training_labels
from .tools.datasource import agent_state_dir, atomic_write_json


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--as-of',type=float,default=None)
    args=parser.parse_args()
    context=authenticate('Bearer '+os.environ.get('FK_LABEL_EXPORT_TOKEN',''))
    bundle=export_labels(context,time.time() if args.as_of is None else args.as_of)
    training_labels(bundle,context.tenant,context.app)
    with data_context(context):
        path=agent_state_dir()/'training_labels'/(bundle['dataset_digest']+'.json')
        atomic_write_json(path,bundle)
    print(json.dumps({'path':str(path),'rows':len(bundle['rows']),'dataset_digest':bundle['dataset_digest']}))

if __name__=='__main__':main()
