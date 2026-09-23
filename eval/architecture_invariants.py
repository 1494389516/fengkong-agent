#!/usr/bin/env python3
"""Non-optional architectural safety checks for the risk-control boundary."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def require(path, *needles):
    text=(ROOT/path).read_text(encoding="utf-8")
    missing=[n for n in needles if n not in text]
    if missing:
        raise SystemExit(f"{path}: missing invariant(s): {missing}")

require("agent/collector.py",
        "context.require('reports.write')",
        "event_bus().publish('risk.evidence.accepted'",
        "db.commit();return receipt")
require("agent/event_bus.py",
        "class LocalEventBus",
        "integration_events",
        "connection=None")
require("agent/tools/online_store.py",
        "BEGIN IMMEDIATE",
        "INSERT INTO outbox",
        "tenant, app, event_id")
require("agent/runtime_bundle.py",
        "runtime bundle tenant/app scope mismatch",
        "SignedBundleReader")
require("agent/control_plane.py",
        "proposer cannot approve own bundle",
        "baseline activation changed",
        "evidence digest binding required")
require("serve.py",
        'if self.path == "/reports"',
        'if self.path == "/attestation/challenge"',
        'elif self.path == "/attestation/enroll"')
require("agent/graph_risk.py",
        "identity_trust",
        "server_bound",
        "community_risk_density",
        "association_features_only")
require("agent/collector.py",
        "result['server_graph'] = graph")
require("deploy/compose.yaml",
        "graph-worker:",
        "agent.graph_worker")

require("agent/graph_store.py",
        'data_dir()/"graph.sqlite3"',
        "class SQLiteGraphStore")
require("agent/online_feature_store.py",
        'data_dir()/"features.sqlite3"',
        "class SQLiteOnlineFeatureStore")
require("agent/graph_algorithms.py",
        "class CommunityV1",
        "algorithm_version",
        "association_features_only")
require("agent/graph_risk.py",
        'topic="risk.evidence.accepted"',
        "online_feature_store().put")
require("deploy/compose.yaml",
        "FK_DATA_DIR: /tenant",
        "FK_GRAPH_ALGORITHM: community_v1")
print("Agent architecture invariants: PASS")
