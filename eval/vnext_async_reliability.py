"""Regression coverage for topic isolation, leases and graph invalidation."""
import os
import tempfile
import time
import unittest
from unittest.mock import patch
from agent.event_bus import event_bus
from agent import graph_risk


class AsyncReliability(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        env = patch.dict(os.environ, {'FK_DATA_DIR': tmp.name,
            'FK_GRAPH_ALGORITHM': 'community_v1', 'FK_GRAPH_SHADOW_ALGORITHM': ''})
        env.start()
        self.addCleanup(env.stop)

    def observation(self, eid, device, uid):
        return dict(evidence_id=eid, tenant_id='t', app_id='a', device_id=device,
            entity_generation='g', uid=uid, identity_trust='server_bound',
            observed_at=time.time(), recorded_at=time.time())

    def test_topic_retry_limits_are_independent(self):
        bus = event_bus('shared')
        bus.publish('a', 'a', {})
        bus.claim('a', lease_seconds=1, max_attempts=5, now=time.time()-10)
        bus.claim('b', max_attempts=1)
        self.assertEqual(bus.stats(topic='a')['dead_letters'], 0)
        self.assertEqual(len(bus.claim('a', max_attempts=5)), 1)

    def test_nonfinite_and_overflow_leases_rejected(self):
        for group in (None, 'g'):
            bus = event_bus(group)
            for kwargs in ({'lease_seconds': float('nan')}, {'lease_seconds': float('inf')},
                           {'now': float('nan')}, {'now': float('inf')},
                           {'now': 1e308, 'lease_seconds': 1e308}):
                with self.subTest(group=group, kwargs=kwargs):
                    with self.assertRaises(ValueError):
                        bus.claim('a', **kwargs)

    def test_slow_batch_does_not_exhaust_unprocessed_events(self):
        clock = [time.time()]
        real_ingest = graph_risk.ingest_observation
        def slow(obs):
            result = real_ingest(obs)
            clock[0] += 16
            return result
        with patch('time.time', side_effect=lambda: clock[0]), patch.object(
                graph_risk, 'ingest_observation', side_effect=slow):
            bus = event_bus()
            for i in range(12):
                bus.publish('risk.evidence.accepted', str(i), self.observation(str(i), str(i), 'u'))
            result = graph_risk.consume_pending(limit=100)
            self.assertEqual(result['processed'], 12)
            self.assertEqual(result['failed'], [])
            self.assertEqual(bus.stats()['pending'], 0)
            self.assertEqual(bus.stats()['dead_letters'], 0)

    def test_ack_failure_is_reported(self):
        bus = event_bus()
        bus.publish('risk.evidence.accepted', '1', self.observation('1', 'D', 'u'))
        with patch('agent.event_bus.LocalEventBus.acknowledge', return_value=False):
            result = graph_risk.consume_pending(limit=1)
        self.assertEqual(result['processed'], 0)
        self.assertEqual(result['failed'][0]['error'], 'LeaseLost')

    def test_renewal_is_fenced_and_group_isolated(self):
        for group in (None, 'worker'):
            bus = event_bus(group)
            topic = str(group)
            bus.publish(topic, 'k', {})
            now = time.time()
            first = bus.claim(topic, lease_seconds=30, now=now)[0]
            self.assertFalse(bus.renew(first.event_id, 'wrong', now=now+20))
            self.assertTrue(bus.renew(first.event_id, first.lease_token, now=now+20))
            self.assertEqual(bus.claim(topic, now=now+31), [])
            self.assertFalse(bus.renew(first.event_id, first.lease_token, now=now+51))
            second = bus.claim(topic, now=now+51)[0]
            self.assertFalse(bus.renew(first.event_id, first.lease_token, now=now+52))
            self.assertTrue(bus.renew(second.event_id, second.lease_token, now=now+52))
            if group:
                self.assertFalse(event_bus('other').renew(second.event_id, second.lease_token, now=now+52))

    def test_guard_renews_in_callers_context_and_stops(self):
        from contextvars import ContextVar
        from threading import Event
        from agent.lease_guard import keep_lease, LeaseLost
        marker = ContextVar('test_dataset', default='wrong')
        token = marker.set('tenant-a')
        self.addCleanup(marker.reset, token)
        bus = event_bus()
        bus.publish('guard', 'k', {})
        event = bus.claim('guard')[0]
        renewed = Event()
        contexts = []
        original = bus.renew
        def renew(*args, **kwargs):
            contexts.append(marker.get())
            result = original(*args, **kwargs)
            renewed.set()
            return result
        with patch.object(bus, 'renew', side_effect=renew):
            with keep_lease(bus, event, interval=0.01):
                self.assertTrue(renewed.wait(2))
        self.assertTrue(contexts)
        self.assertEqual(set(contexts), {'tenant-a'})
        renewed.clear()
        def reject(*args, **kwargs):
            renewed.set()
            return False
        with patch.object(bus, 'renew', side_effect=reject):
            with self.assertRaises(LeaseLost):
                with keep_lease(bus, event, interval=0.01):
                    self.assertTrue(renewed.wait(2))

    def test_indirect_neighbor_is_invalidated_then_refreshed(self):
        for eid, device, uid in [('1','A','u1'), ('2','B','u1'), ('3','B','u2'), ('4','C','u2')]:
            graph_risk.ingest_observation(self.observation(eid, device, uid))
        graph_risk.refresh_dirty_devices()
        graph_risk.ingest_observation(self.observation('5','D','u1'))
        self.assertIsNone(graph_risk.lookup('t','a','C','g'))
        graph_risk.refresh_dirty_devices()
        served = graph_risk.lookup('t','a','C','g')
        expected = graph_risk.recompute_device('t','a','C','g')
        for key in ('component_density','community_id','community_device_count'):
            self.assertEqual(served[key], expected[key])


if __name__ == '__main__':
    unittest.main()
