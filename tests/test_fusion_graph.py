"""C27/C28 point-in-time association evidence regressions."""
import unittest
from unittest.mock import patch
import networkx as nx
from agent.tools import graph
from agent.tools.blacklist import active_records


def event(uid, device, ts, ip='shared'):
    return dict(uid=uid, device_id=device, ip=ip, ts=ts)


class FusionGraphTests(unittest.TestCase):
    def test_C27_all_ip_types_are_weak(self):
        for typ in ('residential', 'mobile', 'idc', 'proxy', 'unknown'):
            with self.subTest(typ=typ), patch.object(graph, 'load_events', return_value=[event('a', 'd1', 90), event('b', 'd2', 90)]), patch.object(graph, 'ip_info', return_value={'type': typ}):
                g = graph._build_graph(as_of_ts=100, window_seconds=20)
                component = nx.node_connected_component(graph._strong_subgraph(g), ('uid', 'a'))
                self.assertNotIn(('uid', 'b'), component)

    def test_C27_window_excludes_future_and_old_reinstall(self):
        with patch.object(graph, 'load_events', return_value=[event('old', 'd', 1), event('a', 'd', 90), event('future', 'd', 100)]):
            g = graph._build_graph(as_of_ts=100, window_seconds=20)
        self.assertIn(('uid', 'a'), g)
        self.assertNotIn(('uid', 'old'), g)
        self.assertNotIn(('uid', 'future'), g)
        self.assertEqual(g[('uid', 'a')][('device_id', 'd')]['last_seen'], 90)

    def test_C27_supernode_cannot_merge_all_accounts(self):
        with patch.object(graph, 'load_events', return_value=[event(str(i), 'shared', 90) for i in range(30)]):
            g = graph._build_graph(as_of_ts=100, window_seconds=20)
        c = nx.node_connected_component(graph._strong_subgraph(g), ('uid', '0'))
        self.assertEqual(sum(k == 'uid' for k, v in c), 1)
        self.assertIn('high_degree_resource', g[('uid', '0')][('device_id', 'shared')]['weak_reason'])

    def test_C27_empty_device_cannot_merge_accounts(self):
        with patch.object(graph, 'load_events', return_value=[event('a', '', 90), event('b', '', 90)]):
            g = graph._build_graph(as_of_ts=100, window_seconds=20)
        self.assertNotIn(('device_id', ''), g)

    def test_C27_invalid_time_is_rejected(self):
        for ts in (float('nan'), float('inf'), True):
            with self.subTest(ts=ts), self.assertRaises(ValueError):
                graph._build_graph(as_of_ts=ts)

    def test_C27_component_is_bounded_and_neutral(self):
        events = []
        for i in range(200):
            events.extend([event(str(i), str(i), 90), event(str(i + 1), str(i), 90)])
        with patch.object(graph, 'load_events', return_value=events), patch.object(graph, 'active_records', return_value=[]), patch.object(graph, 'load_labels', return_value={}):
            info = graph.component_summary('0', as_of_ts=100, window_seconds=20)
        self.assertLessEqual(info['account_count'], 100)
        self.assertTrue(info['truncated'])
        self.assertEqual(info['interpretation'], 'association_only')

    def test_C28_graph_and_rules_share_expiry_at_replay_time(self):
        from agent.tools import blacklist
        records = [dict(dimension='uid', value='a', list='black', reason='test', expires_at='2020-01-01')]
        for ts, expected in ((1577836801, True), (1577923200, False)):
            with self.subTest(ts=ts), patch.object(blacklist, 'load_blacklist', return_value=records), patch.object(graph, 'load_events', return_value=[event('a', 'd', ts - 1)]), patch.object(graph, 'load_labels', return_value={}):
                info = graph.component_summary('a', as_of_ts=ts, window_seconds=20)
                self.assertEqual(bool(info['blacklist_hits']), expected)
                self.assertEqual(bool(info['blacklist_hits']), bool(active_records('uid', 'a', ts)))
                if expected:
                    self.assertEqual(info['blacklist_evidence'][0]['expires_at'], '2020-01-01')

    def test_C26_rule_white_lookup_is_business_scope_bound(self):
        from agent.tools import rules
        from agent.tools.policy import DEFAULTS
        p = dict(DEFAULTS, _version='test', _overridden=False)
        with patch.object(rules, '_uid_features', return_value=None), patch.object(rules, 'active_policy', return_value=p), patch.object(rules, 'active_records', return_value=[]) as lookup:
            rules._local_rule_eval(dict(uid='a', type='order'), enabled_rules=['R001'])
        white_calls = [c for c in lookup.call_args_list if c.kwargs.get('lists') == ('white',)]
        self.assertTrue(white_calls)
        self.assertEqual(white_calls[0].kwargs.get('scope'), 'order')

    def test_C27_weak_expansion_has_an_explicit_budget(self):
        events = [event('a', 'd', 90, ip=str(i)) for i in range(500)]
        with patch.object(graph, 'load_events', return_value=events), patch.object(graph, 'active_records', return_value=[]), patch.object(graph, 'load_labels', return_value={}):
            info = graph.component_summary('a', as_of_ts=100, window_seconds=20)
        self.assertLessEqual(len(info['weak_ips']), 200)
        self.assertTrue(info['truncated'])
