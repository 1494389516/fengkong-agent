"""Legal missing resource identifiers must not crash or create shared entities."""
from unittest.mock import patch
import pandas as pd
import pytest
from agent.tools import featurelib


def event(uid="u", ts=1, **extra):
    return {"uid": uid, "ts": ts, "type": "coupon_claim", **extra}


def test_account_history_without_optional_resources():
    with patch.object(featurelib, "_account_events", return_value=[event(), event(ts=2)]):
        result = featurelib.account_features("u", as_of_ts=3)
    assert result["event_count"] == 2
    assert result["distinct_ip"] == result["distinct_device"] == 0
    assert result["ips"] == result["devices"] == []
    assert result["missing_ip_events"] == result["missing_device_events"] == 2


@pytest.mark.parametrize("missing", [None, "", "   "])
def test_missing_resource_is_never_a_shared_entity(missing):
    events = [event("u", ip=missing, device_id=missing), event("v")]
    with patch.object(featurelib, "load_events", return_value=events):
        for dimension in ("ip", "device_id"):
            result = featurelib.accounts_per(dimension, missing)
            assert result["count"] == 0
            assert result["accounts"] == []
            assert result["missing"] is True


def test_accounts_per_skips_missing_and_respects_time():
    events = [event("missing"), event("before", ts=1, ip="192.0.2.1"),
              event("after", ts=3, ip="192.0.2.1")]
    with patch.object(featurelib, "load_events", return_value=events):
        result = featurelib.accounts_per("ip", "192.0.2.1", as_of_ts=2)
    assert result["accounts"] == ["before"]


def test_batch_all_missing_columns_and_empty_dataset():
    with patch.object(featurelib, "load_events", return_value=[event(), event("v")]):
        result = featurelib.batch_features()
    assert list(result["distinct_device"]) == [0, 0]
    assert list(result["distinct_ip"]) == [0, 0]
    assert result["shared_device_accounts"].isna().all()
    with patch.object(featurelib, "load_events", return_value=[]):
        assert featurelib.batch_features().empty


def test_batch_excludes_blank_entities_and_preserves_real_sharing():
    events = [event("missing", device_id="", ip=" "),
              event("u", device_id="d1", ip="192.0.2.1"),
              event("v", device_id="d1", ip="192.0.2.1"), event("u", ts=2)]
    with patch.object(featurelib, "load_events", return_value=events):
        result = featurelib.batch_features()
    assert pd.isna(result.loc["missing", "shared_device_accounts"])
    assert result.loc["missing", "distinct_ip"] == 0
    assert result.loc["u", "shared_device_accounts"] == 2
    assert result.loc["u", "distinct_device"] == 1


def test_batch_numeric_matrix_supports_existing_chart_consumers():
    events = [event("missing"), event("u", device_id="d1", ip="192.0.2.1")]
    with patch.object(featurelib, "load_events", return_value=events):
        result = featurelib.batch_features()
    matrix = result[["distinct_device", "shared_device_accounts"]].to_numpy()
    assert matrix.dtype.kind in "fiu"
    assert pd.isna(result.loc["missing", "shared_device_accounts"])
