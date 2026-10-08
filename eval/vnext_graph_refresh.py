import os
import tempfile
import time
import unittest
from unittest.mock import patch
from agent import graph_risk
from agent.graph_store import graph_store
from agent.event_bus import event_bus
from agent.graph_worker_health import write_heartbeat, read_health


class GraphRefresh(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        env=patch.dict(os.environ,{'FK_DATA_DIR':tmp.name,'FK_GRAPH_ALGORITHM':'community_v1','FK_GRAPH_SHADOW_ALGORITHM':''})
        env.start();self.addCleanup(env.stop)

    def add(self,e,d,u):
        now=time.time()
        graph_risk.ingest_observation(dict(evidence_id=e,tenant_id='t',app_id='a',device_id=d,
            entity_generation='g',uid=u,identity_trust='server_bound',observed_at=now,recorded_at=now))

    def test_continuous_unrelated_reports_preserve_105_devices(self):
        for i in range(105):self.add(str(i),'D%03d'%i,'u%d'%i)
        graph_risk.refresh_dirty_devices(limit=1000)
        for i in range(3):
            self.add('live'+str(i),'D000','u0')
            graph_risk.refresh_dirty_devices(limit=100)
            self.assertIsNotNone(graph_risk.lookup('t','a','D104','g'))
            self.assertEqual(graph_store().dirty_devices(1000),[])

    def test_requeued_head_cannot_starve_existing_tail(self):
        store=graph_store()
        store.mark_dirty('t','a',[('A','g'),('Z','g')])
        store.clear_dirty('t','a','A','g')
        store.mark_dirty('t','a',[('A','g')])
        self.assertEqual(store.dirty_devices(1)[0][2],'Z')

    def test_pending_projection_is_not_healthy(self):
        self.add('a','A','u');self.add('b','B','u')
        write_heartbeat({'processed':1,'failed':[]},event_bus().stats())
        health=read_health()
        self.assertEqual(health['level'],'degraded')
        self.assertGreater(health['projection']['pending'],0)
        self.assertLess(health['projection']['availability'],1)

    def test_connected_tail_progresses_under_continuous_updates(self):
        for i in range(105):self.add(str(i),'D%03d'%i,'shared')
        graph_risk.refresh_dirty_devices(limit=1000)
        self.add('live1','D000','shared')
        graph_risk.refresh_dirty_devices(limit=100)
        self.assertIsNone(graph_risk.lookup('t','a','D104','g'))
        self.add('live2','D000','shared')
        graph_risk.refresh_dirty_devices(limit=100)
        self.assertIsNotNone(graph_risk.lookup('t','a','D104','g'))

    def test_legacy_queue_migrates_without_losing_pending_work(self):
        import sqlite3
        from pathlib import Path
        db=sqlite3.connect(Path(os.environ['FK_DATA_DIR'])/'graph.sqlite3')
        db.execute('CREATE TABLE dirty_devices(tenant TEXT,app TEXT,device_id TEXT,entity_generation TEXT,PRIMARY KEY(tenant,app,device_id,entity_generation))')
        db.execute("INSERT INTO dirty_devices VALUES('t','a','Z','g')")
        db.commit();db.close()
        store=graph_store();store.mark_dirty('t','a',[('A','g')])
        self.assertEqual(store.dirty_devices(1)[0][2],'Z')
        self.assertEqual(store.dirty_stats()['pending'],2)

    def test_failed_refresh_does_not_monopolize_queue(self):
        self.add('a','A','u1');self.add('z','Z','u2')
        store=graph_store();store.mark_dirty('t','a',[('A','g'),('Z','g')])
        with patch('agent.graph_risk.graph_algorithm',side_effect=RuntimeError('offline')):
            self.assertEqual(len(graph_risk.refresh_dirty_devices(limit=1)['failed']),1)
        self.assertEqual(store.dirty_devices(1)[0][2],'Z')
        self.assertEqual(store.dirty_stats()['pending'],2)

    def test_node_budget_and_temporal_clock_fall_back_to_scope(self):
        self.add('a','A','u1');self.add('b','B','u2')
        with patch('agent.graph_risk.MAX_NODES',4):
            self.add('c','C','u3')
            self.assertIsNone(graph_risk.lookup('t','a','A','g'))
        graph_risk.refresh_dirty_devices()
        with patch.dict(os.environ,{'FK_GRAPH_ALGORITHM':'temporal_community_v1'}):
            self.add('d','D','u4')
            self.assertIsNone(graph_risk.lookup('t','a','A','g'))

    def test_snapshot_overflow_invalidates_unrelated_old_features(self):
        self.add('a','A','u1');self.add('b','B','u2')
        with patch('agent.graph_risk.MAX_ROWS',2):
            self.add('c','C','u3')
            self.assertIsNone(graph_risk.lookup('t','a','A','g'))
            graph_risk.refresh_dirty_devices()
            self.assertIsNone(graph_risk.lookup('t','a','A','g'))


if __name__=='__main__':unittest.main()
