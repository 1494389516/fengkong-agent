import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from agent.tools import datasource, featurelib, charts, agent_drift, readiness

class CompletionDatasourceTests(unittest.TestCase):
    def test_bundle_list_is_actual_snapshot(self):
        row={'dimension':'uid','value':'a','list':'black','reason':'verified'}
        with patch('agent.runtime_bundle.current_bundle',return_value={'list':{'records':[row]}}):
            self.assertEqual(datasource.load_blacklist(),[row])

    def test_sql_features_refresh_without_fixture_file(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ,{'FK_DATA_DIR':tmp}), patch('agent.runtime_bundle.current_bundle',return_value=None):
            db=sqlite3.connect(str(Path(tmp)/'online.sqlite3'))
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('CREATE TABLE events (tenant TEXT,app TEXT,event_id TEXT,occurred_at REAL,recorded_at REAL,body TEXT)')
            def insert(i):
                e=dict(uid='a',ts=i,type='login',recorded_at=i)
                db.execute('INSERT INTO events VALUES (?,?,?,?,?,?)',('t','app',str(i),i,i,json.dumps(e)))
                db.commit()
            insert(1)
            self.assertEqual(featurelib.account_features('a')['event_count'],1)
            insert(2)
            self.assertEqual(featurelib.account_features('a')['event_count'],2)
            db.close()

    def test_chart_output_is_current_tenant_directory(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(datasource,'output_dir',return_value=Path(tmp)), patch.object(charts.plt,'close'):
            fig=Mock()
            result=charts._save(fig,'test.png')
            self.assertEqual(Path(fig.savefig.call_args.args[0]),Path(tmp)/'charts'/'test.png')
            self.assertEqual(Path(result),Path(tmp)/'charts'/'test.png')

    def test_drift_reads_current_tenant_directory(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(datasource,'output_dir',return_value=Path(tmp)):
            (Path(tmp)/'agent_runs.jsonl').write_text('{}\n')
            result=agent_drift.agent_behavior_drift()
            self.assertIn('当前 1 条', result['note'])

    def test_sql_graph_filter_and_limit(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ,{'FK_DATA_DIR':tmp}):
            db=sqlite3.connect(str(Path(tmp)/'online.sqlite3'))
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('CREATE TABLE events (tenant TEXT,app TEXT,event_id TEXT,occurred_at REAL,recorded_at REAL,body TEXT)')
            for i,ts,recorded in [('old',1,1),('late',90,101),('now',90,99),('future',101,101),('extra',91,99)]:
                db.execute('INSERT INTO events VALUES (?,?,?,?,?,?)',('t','a',i,ts,recorded,json.dumps(dict(uid=i,ts=ts,recorded_at=recorded))))
            db.commit();db.close()
            rows=datasource.load_events(limit=1,as_of_ts=100,window_seconds=20)
            self.assertEqual([r['uid'] for r in rows],['now'])
