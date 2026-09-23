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
        "graph_algorithm",
        "online_feature_store")
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
        "class TemporalCommunityV1",
        "temporal_half_life_seconds",
        "association_features_only")
require("agent/graph_risk.py",
        'topic="risk.evidence.accepted"',
        "store.put",
        "SHADOW_FEATURE_SET",
        "shadow_of=primary_name")
require("deploy/compose.yaml",
        "FK_DATA_DIR: /tenant",
        "FK_GRAPH_ALGORITHM: community_v1")
print("Agent architecture invariants: PASS")

require("agent/graph_training.py",
        "knowledge_cutoff",
        "future label leakage",
        "snapshot_fingerprint")
require("agent/graph_model_adapter.py",
        "class CallableGNNAdapter",
        "GNN score must be in [0,1]",
        "not constructible from arbitrary runtime config")

require("agent/graph_model_eval.py",
        "snapshot_fingerprint",
        "account_aggregation",
        "promotion_significance")
require("agent/graph_model_registry.py",
        "champion activation requires signed Control Plane release",
        "challenger requires recorded evaluation")

require("agent/graph_model_registry.py",
        "artifact_digest must be sha256 hex",
        "unsupported graph runtime loader",
        "builtin_graph_algorithm_v1")
require("agent/graph_release.py",
        "runtime loader is not production-supported",
        "graph release not ready",
        "component_digest")
