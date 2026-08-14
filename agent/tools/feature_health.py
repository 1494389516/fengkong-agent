# -*- coding: utf-8 -*-
"""特征健康检查:建模/回测/策略分析之前的健康门槛。

agent 在建模、回测、策略分析前,应该先知道特征当前是否健康 —— 五个维度:
  missingness   缺失率(订单特征对无订单账号天然缺失,阈值分级 ok/warn/fail)
  freshness     数据新鲜度(最后事件距今天数,>90 天 warn:陈旧数据结论无时效)
  distribution  分布漂移(当前分位数 vs 策略快照,相对变化 >50% warn:
                "养基线"或数据面变化要先于结论发现)
  value_range   取值域(负值等非法值 = fail)
  enum_drift    枚举漂移(未知事件类型 = fail,规则与特征可能静默失真)

输出 summary:ok / warn / fail,带 dataset_fingerprint 与逐项明细。
"""
from datetime import datetime, timezone
from typing import Any, Dict, List

from . import tool
from .dataset import dataset_fingerprint
from .datasource import load_events
from .featurelib import account_features, population_baseline
from .policy import latest_baseline_snapshot

MODELING_FEATURES = ("event_count", "distinct_ip", "distinct_device",
                     "coupon_claims", "order_amount_max", "min_gap_seconds",
                     "shared_device_accounts")
EVENT_TYPES = ("login", "order", "coupon_claim")
WARN_NULL_RATE = 0.25
FAIL_NULL_RATE = 0.5
WARN_AGE_DAYS = 90
WARN_REL_SHIFT = 0.5

_SEV = {"ok": 0, "warn": 1, "fail": 2}


def _missingness(uid_features: Dict[str, Dict]) -> Dict:
    n = len(uid_features)
    per: Dict[str, Dict] = {}
    for f in MODELING_FEATURES:
        missing = sum(1 for d in uid_features.values()
                      if d.get(f) is None)
        rate = missing / n if n else 0.0
        level = ("ok" if rate < WARN_NULL_RATE
                 else ("warn" if rate < FAIL_NULL_RATE else "fail"))
        per[f] = {"null_rate": round(rate, 3), "level": level}
    worst = max((_SEV[d["level"]] for d in per.values()), default=0)
    return {"level": ("ok" if worst == 0 else ("warn" if worst == 1 else "fail")),
            "features": per}


def _freshness(events: List[Dict]) -> Dict:
    if not events:
        return {"level": "warn", "note": "无事件,新鲜度不可评"}
    last = max(e["ts"] for e in events)
    age_days = (datetime.now(timezone.utc).timestamp() - last) / 86400.0
    return {"level": "ok" if age_days < WARN_AGE_DAYS else "warn",
            "last_event_ts": last, "age_days": round(age_days, 1),
            "warn_threshold_days": WARN_AGE_DAYS}


def _distribution() -> Dict:
    cur = population_baseline()
    snap_version, snap = latest_baseline_snapshot()
    if snap is None:
        return {"level": "ok", "note": "无基线快照,分布漂移不可比(n/a)",
                "snapshot_version": None}
    issues = []
    for feat in MODELING_FEATURES:
        cs, ss = cur.get(feat), snap.get(feat)
        if not cs or not ss:
            continue
        for p in ("p50", "p90", "p99"):
            cv, sv = cs.get(p), ss.get(p)
            if cv is None or sv is None or sv == 0:
                continue
            rel = abs(cv - sv) / abs(sv)
            if rel > WARN_REL_SHIFT:
                issues.append({"feature": feat, "percentile": p,
                               "current": cv, "snapshot": sv,
                               "rel_change": round(rel, 2)})
    return {"level": "warn" if issues else "ok", "issues": issues,
            "snapshot_version": snap_version}


def _range(uid_features: Dict[str, Dict]) -> Dict:
    issues = []
    for uid, d in uid_features.items():
        for f in ("event_count", "distinct_ip", "distinct_device",
                  "coupon_claims", "order_amount_max", "min_gap_seconds"):
            v = d.get(f)
            if v is not None and v < 0:
                issues.append({"uid": uid, "feature": f, "value": v})
    return {"level": "fail" if issues else "ok", "issues": issues[:10]}


def _enums(events: List[Dict]) -> Dict:
    types = {e["type"] for e in events}
    unknown = sorted(t for t in types if t not in EVENT_TYPES)
    return {"level": "fail" if unknown else "ok",
            "known_types": list(EVENT_TYPES), "unknown_types": unknown}


@tool(
    name="feature_health_check",
    description=(
        "特征健康检查:建模/回测/策略分析前的门槛 —— 缺失率、新鲜度、分布"
        "漂移(对比策略基线快照)、取值域、枚举漂移,输出 ok/warn/fail 与"
        "明细。发现 fail 时必须先修数据面再下结论。"
    ),
    parameters={"type": "object", "properties": {}},
)
def feature_health_check():
    events = load_events()
    uids = sorted({e["uid"] for e in events})
    uid_features = {}
    for u in uids:
        f = account_features(u)
        if f.get("found"):
            f.setdefault("shared_device_accounts", 0)
            uid_features[u] = f
    checks = {
        "missingness": _missingness(uid_features),
        "freshness": _freshness(events),
        "distribution_shift": _distribution(),
        "value_range": _range(uid_features),
        "enum_drift": _enums(events),
    }
    worst = max((_SEV[c["level"]] for c in checks.values()), default=0)
    summary = ("ok" if worst == 0 else ("warn" if worst == 1 else "fail"))
    return {
        "summary": summary,
        "checks": checks,
        "accounts_checked": len(uid_features),
        "dataset_fingerprint": dataset_fingerprint(),
        "note": ("fail 级问题(取值域/枚举)会让规则与特征静默失真,"
                 "先修数据面;warn 级(缺失/陈旧/漂移)影响结论时效,引用须声明"),
    }
