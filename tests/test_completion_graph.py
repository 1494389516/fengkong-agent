"""Completion C05/C06/C27/C28/G05: source, generations, and knowledge time."""
import unittest
from unittest.mock import patch
import networkx as nx
from agent.tools import graph, featurelib

class CompletionGraphTests(unittest.TestCase):
    def build(self, events):
        with patch.object(graph, 'load_events', return_value=events):
            return graph._build_graph(100, 20)

    def test_late_arrival_does_not_leak_into_replay(self):
        g = self.build([dict(uid='late', device_id='d', ts=90, recorded_at=101),
                        dict(uid='visible', device_id='e', ts=90, recorded_at=99)])
        self.assertNotIn(('uid', 'late'), g)
        self.assertIn(('uid', 'visible'), g)

    def test_reinstall_generations_never_merge(self):
        g = self.build([dict(uid=u, device_id='same', ts=90, identity_trust='server_bound',
                             entity_generation=generation) for u, generation in [('old','1'),('new','2')]])
        c = nx.node_connected_component(graph._strong_subgraph(g), ('uid','old'))
        self.assertNotIn(('uid','new'), c)

    def test_asserted_device_never_strong(self):
        g = self.build([dict(uid=u, device_id='claimed', ts=90, identity_trust='client_asserted') for u in ('a','b')])
        c = nx.node_connected_component(graph._strong_subgraph(g), ('uid','a'))
        self.assertNotIn(('uid','b'), c)

    def test_hardware_vectors_are_not_entity_keys(self):
        g = self.build([dict(uid=u, ts=90, hardware_vector={'model':'same'}) for u in ('a','b')])
        self.assertEqual(len(g.edges), 0)

    def test_shared_exits_do_not_join_accounts(self):
        for environment in ('cgnat','dormitory','enterprise','family'):
            with self.subTest(environment=environment):
                g = self.build([dict(uid=u, ip=environment, ts=90) for u in ('a','b')])
                self.assertEqual(nx.node_connected_component(graph._strong_subgraph(g), ('uid','a')), {('uid','a')})

    def test_feature_history_excludes_late_records(self):
        events=[dict(uid='a', ts=90, recorded_at=101, type='login')]
        with patch.object(featurelib, '_events_by_uid', return_value={'a':events}):
            self.assertFalse(featurelib.account_features('a',100)['found'])

    def test_reverse_count_excludes_late_records(self):
        with patch.object(featurelib, 'load_events', return_value=[dict(uid='a',ts=90,recorded_at=101,device_id='d')]):
            self.assertEqual(featurelib.accounts_per('device_id','d',100)['count'],0)

    def test_graph_requests_bounded_storage_read(self):
        with patch.object(graph, 'load_events', return_value=[]) as load:
            graph._build_graph(100,20)
        self.assertEqual(load.call_args.kwargs['limit'], graph.MAX_GRAPH_EVENTS+1)

    def test_runtime_bundle_caps_graph_work(self):
        with patch('agent.runtime_bundle.current_bundle', return_value={'graph':{'max_events':1}}), patch.object(graph,'load_events',return_value=[dict(uid='a',ts=90),dict(uid='b',ts=90)]) as load:
            g=graph._build_graph(100,20)
        self.assertTrue(g.graph['truncated'])
        self.assertEqual(load.call_args.kwargs['limit'],2)
        self.assertNotIn(('uid','b'),g)

    def test_runtime_catalog_mismatch_fails_closed(self):
        with patch('agent.runtime_bundle.current_bundle',return_value={'feature':{'catalog_version':'unknown'}}):
            with self.assertRaises(ValueError):
                featurelib.accounts_per('device_id','d',100)

    def test_server_bound_without_generation_is_not_strong(self):
        g=self.build([dict(uid=u,device_id='d',ts=90,identity_trust='server_bound') for u in ('a','b')])
        self.assertNotIn(('uid','b'),nx.node_connected_component(graph._strong_subgraph(g),('uid','a')))

    def test_generation_blacklist_uses_canonical_resource(self):
        g=self.build([dict(uid='a',device_id='canonical',ts=90,identity_trust='server_bound',entity_generation='2')])
        with patch.object(graph,'active_records',return_value=[]) as lookup:
            graph._active_blacklist(g)
        self.assertIn('canonical',[call.args[1] for call in lookup.call_args_list])
