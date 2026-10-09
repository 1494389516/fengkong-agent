"""Crash a real DBOS workflow between completed and incomplete investigation steps.

No model/provider calls, credentials, real cases, or production actions are used.
The probe uses the real investigation plan validator and PostgreSQL checkpoints.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid


def worker(root, db_schema):
    from dbos import DBOS, SetWorkflowID
    from agent.investigation_plan import template, validate
    from agent.evidence_snapshot import digest

    def record(stage):
        with (root/'attempts.jsonl').open('a') as handle:
            handle.write(json.dumps({'stage':stage})+'\n');handle.flush();os.fsync(handle.fileno())

    @DBOS.step(name='pinned_evidence')
    def evidence():
        record('evidence')
        return {'case_id':'fixture','entity_ref':'u','decision':{'event':{'event_id':'e'}},
                'budget':{'max_tool_calls':3},
                'allowed_tools':['get_event_evidence','graph_relations','feature_stats']}

    @DBOS.step(name='validated_plan')
    def plan_step(snapshot):
        record('plan')
        plan=template(snapshot,snapshot['allowed_tools'])
        validate(plan,snapshot,snapshot['allowed_tools'])
        return {'plan':plan,'snapshot_digest':digest(snapshot)}

    @DBOS.step(name='report_fixture')
    def report(plan):
        record('report')
        (root/'report-started').touch()
        deadline=time.monotonic()+45
        while not (root/'resume').exists():
            if time.monotonic()>deadline:raise TimeoutError('probe coordinator did not resume')
            time.sleep(.05)
        return {'status':'fixture_complete','plan_digest':digest(plan),'production_action_authorized':False}

    @DBOS.workflow(name='investigation_recovery_probe')
    def workflow():
        return report(plan_step(evidence()))

    DBOS(config={'name':'fengkong-recovery-probe','application_version':'probe-v1',
                 'system_database_url':os.environ['FK_DBOS_DATABASE_URL'],
                 'dbos_system_schema':db_schema,'executor_id':'local',
                 'run_admin_server':False,'enable_otlp':False,'log_level':'ERROR'})
    DBOS.launch()
    try:
        if (root/'resume').exists():
            result=DBOS.retrieve_workflow('fixed-investigation').get_result()
        else:
            with SetWorkflowID('fixed-investigation'):
                result=DBOS.start_workflow(workflow).get_result()
        (root/'result.json').write_text(json.dumps(result))
    finally:DBOS.destroy()


def probe():
    if not os.environ.get('FK_DBOS_DATABASE_URL'):
        raise ValueError('FK_DBOS_DATABASE_URL must name an isolated PostgreSQL experiment database')
    db_schema='dbos_probe_'+uuid.uuid4().hex[:16]
    with tempfile.TemporaryDirectory() as directory:
        root=Path(directory)
        command=[sys.executable,'-m',__name__.replace('__main__','experiments.dbos.recovery_probe'),
                 '--worker',str(root),'--schema',db_schema]
        with (root/'first.log').open('w') as log:
            first=subprocess.Popen(command,stdout=log,stderr=log)
            try:
                deadline=time.monotonic()+40
                while not (root/'report-started').exists():
                    if first.poll() is not None or time.monotonic()>deadline:
                        raise RuntimeError('first worker failed: '+(root/'first.log').read_text()[-5000:])
                    time.sleep(.05)
            finally:
                first.kill();first.wait(timeout=10)
        (root/'resume').touch()
        resumed=subprocess.run(command,capture_output=True,text=True,timeout=60)
        if resumed.returncode:raise RuntimeError('resume failed: '+resumed.stderr[-5000:])
        attempts=[json.loads(line)['stage'] for line in (root/'attempts.jsonl').read_text().splitlines()]
        counts={stage:attempts.count(stage) for stage in ('evidence','plan','report')}
        assert counts=={'evidence':1,'plan':1,'report':2},counts
        result=json.loads((root/'result.json').read_text())
        assert result['status']=='fixture_complete' and result['production_action_authorized'] is False
        print(json.dumps({'recovery':'passed','executions':counts,'schema':db_schema,
            'limitation':'unfinished external effects require application idempotency; no live provider tested'}))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--worker');parser.add_argument('--schema')
    args=parser.parse_args()
    if args.worker:worker(Path(args.worker),args.schema)
    else:probe()
