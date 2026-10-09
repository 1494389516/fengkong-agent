"""Clock and I/O boundary regressions using real heartbeat files and SQLite."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from agent.event_bus import event_bus
from agent.graph_worker_health import write_heartbeat, read_health
from agent.online_feature_store import online_feature_store


class GraphTimeConsistency(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        env=patch.dict(os.environ,{'FK_DATA_DIR':tmp.name});env.start();self.addCleanup(env.stop)
        self.store=online_feature_store()
        self.key=('t','a','device','D','g','graph_risk_v1')

    def test_heartbeat_replaced_during_read_is_not_future(self):
        stats=event_bus().stats()
        write_heartbeat({'processed':0,'failed':[]},stats,now=1000)
        clock=[1000];original=Path.open
        def opening(path,*args,**kwargs):
            if path.name=='graph_worker_health.json' and args==('rb',):
                write_heartbeat({'processed':0,'failed':[]},stats,now=1001)
                clock[0]=1002
            return original(path,*args,**kwargs)
        with patch('time.time',side_effect=lambda:clock[0]),patch.object(Path,'open',opening):
            result=read_health()
        self.assertEqual(result['reason'],'healthy')
        self.assertEqual(result['heartbeat_age_seconds'],1)

    def test_stall_during_read_counts_toward_heartbeat_age(self):
        write_heartbeat({'processed':0,'failed':[]},event_bus().stats(),now=1000)
        clock=[1000];original=Path.open
        def opening(path,*args,**kwargs):
            if path.name=='graph_worker_health.json' and args==('rb',):clock[0]=1011
            return original(path,*args,**kwargs)
        with patch('time.time',side_effect=lambda:clock[0]),patch.object(Path,'open',opening):
            self.assertEqual(read_health()['reason'],'heartbeat_stale')

    def test_future_features_are_not_current_after_clock_rollback(self):
        self.store.put(*self.key,{'truncated':False},computed_at=1100)
        self.assertIsNone(self.store.get(*self.key,max_age=300,now=1000))
        self.assertEqual(self.store.availability_stats(now=1000)['available'],0)
        self.assertIsNotNone(self.store.get(*self.key,max_age=300,now=1100))

    def test_invalidated_feature_stays_unavailable_without_ttl(self):
        self.store.put(*self.key,{'truncated':False},computed_at=1000)
        self.store.invalidate_devices('t','a',[('D','g')])
        self.assertIsNone(self.store.get(*self.key,now=1001))
        self.assertEqual(self.store.availability_stats(now=1001)['available'],0)

    def test_invalid_timestamp_write_preserves_previous_feature(self):
        self.store.put(*self.key,{'v':1},computed_at=1000)
        for stamp in (float('inf'),float('-inf'),float('nan'),True,'1000',0,-1):
            with self.subTest(stamp=stamp):
                with self.assertRaises(ValueError):
                    self.store.put(*self.key,{'v':2},computed_at=stamp)
                self.assertEqual(self.store.get(*self.key,now=1001)['v'],1)

    def test_legacy_infinite_timestamp_is_not_readable_or_available(self):
        self.store.put(*self.key,{'truncated':False},computed_at=1000)
        db=self.store.connect()
        db.execute('UPDATE entity_features SET computed_at=?',(float('inf'),));db.commit();db.close()
        self.assertIsNone(self.store.get(*self.key,max_age=300,now=1001))
        self.assertEqual(self.store.availability_stats(now=1001)['available'],0)

    def test_ttl_boundary_matches_health_and_read(self):
        self.store.put(*self.key,{'truncated':False},computed_at=1000)
        for now,expected in ((1000,1),(1300,1),(1300.01,0)):
            self.assertEqual(int(self.store.get(*self.key,max_age=300,now=now) is not None),expected)
            self.assertEqual(self.store.availability_stats(now=now)['available'],expected)


if __name__=='__main__':unittest.main()
