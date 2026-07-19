# -*- coding: utf-8 -*-
"""统一特征层:所有特征的单一事实源。

规则 / 工具 / 图表全部从这里取数 —— 同一特征只实现一次,避免"规则用的数
和图上画的数对不上"的口径漂移。接真实数仓时,这个文件就是对接面。

两个口径参数(风控特征的命门):
  as_of_ts        取证时点:只用 ts < as_of_ts 的事件。规则评估一个事件时必须
                  传该事件的 ts,否则特征会把"这个事件之后"的行为也算进来
                  (point-in-time 泄漏)—— 回测指标虚高,线上必然对不上。
  window_seconds  时间窗:只用 [anchor - window, anchor) 的事件,anchor 为
                  as_of_ts(未给时取该账号最后事件之后)。行为模式类规则
                  ("领券后短时下单")必须用窗口口径,全历史计数会把一周前
                  的正常行为算进来造成误伤 —— R003 曾在生成大样本上实锤过。
"""
from typing import Dict, List, Optional

from .datasource import load_events


def _account_events(uid: str, as_of_ts: Optional[float] = None) -> List[Dict]:
    return [e for e in load_events()
            if e["uid"] == uid and (as_of_ts is None or e["ts"] < as_of_ts)]


def account_features(uid: str, as_of_ts: Optional[float] = None,
                     window_seconds: Optional[int] = None) -> Dict:
    """单账号行为特征。找不到事件时 found=False(调用方据此判断"无历史")。"""
    evs = _account_events(uid, as_of_ts)
    if window_seconds and evs:
        anchor = as_of_ts if as_of_ts is not None else max(e["ts"] for e in evs) + 1
        evs = [e for e in evs if e["ts"] >= anchor - window_seconds]
    if not evs:
        return {"uid": uid, "found": False, "as_of_ts": as_of_ts, "window_seconds": window_seconds}
    ts = sorted(e["ts"] for e in evs)
    gaps = [b - a for a, b in zip(ts, ts[1:])]
    types: Dict[str, int] = {}
    for e in evs:
        types[e["type"]] = types.get(e["type"], 0) + 1
    amounts = [e["amount"] for e in evs if e["type"] == "order" and e.get("amount") is not None]
    return {
        "uid": uid,
        "found": True,
        "as_of_ts": as_of_ts,
        "window_seconds": window_seconds,
        "event_count": len(evs),
        "distinct_ip": len({e["ip"] for e in evs}),
        "distinct_device": len({e["device_id"] for e in evs}),
        "event_types": types,
        "coupon_claims": types.get("coupon_claim", 0),
        "order_count": len(amounts),
        "order_amount_max": max(amounts) if amounts else None,
        "order_amount_sum": round(sum(amounts), 2) if amounts else 0,
        "min_gap_seconds": min(gaps) if gaps else None,
        "span_seconds": ts[-1] - ts[0],
        "ips": sorted({e["ip"] for e in evs}),
        "devices": sorted({e["device_id"] for e in evs}),
    }


def accounts_per(dimension: str, value: str, as_of_ts: Optional[float] = None) -> Dict:
    """反向基数特征:一个 ip / device_id 上出现过多少账号(含查询账号自身)。
    真实反欺诈里最强的单特征之一 —— 资源被多账号共用是团伙的直接证据。"""
    assert dimension in ("ip", "device_id")
    accounts = sorted({e["uid"] for e in load_events()
                       if e[dimension] == value and (as_of_ts is None or e["ts"] < as_of_ts)})
    return {"dimension": dimension, "value": value,
            "count": len(accounts), "accounts": accounts}


def batch_features():
    """全量账号特征表(pandas DataFrame,index=uid)。群体分析/图表用,
    全历史口径 —— 探索性分析不需要 point-in-time,规则评估才需要。"""
    import pandas as pd  # 惰性导入:规则/评估路径不强依赖 pandas

    df = pd.DataFrame(load_events()).sort_values("ts").reset_index(drop=True)
    feats = df.groupby("uid").agg(
        event_count=("ts", "size"),
        distinct_ip=("ip", "nunique"),
        distinct_device=("device_id", "nunique"),
    )
    feats["coupon_claims"] = (
        df[df["type"] == "coupon_claim"].groupby("uid").size()
        .reindex(feats.index).fillna(0).astype(int))
    feats["order_amount_max"] = (
        df.groupby("uid")["amount"].max() if "amount" in df.columns else float("nan"))
    # df 已按 ts 全局排序,组内顺序即时间序,diff 即相邻间隔
    feats["min_gap_seconds"] = df.groupby("uid")["ts"].diff().groupby(df["uid"]).min()
    # 反向基数:该账号用过的设备中,被最多账号共用的那台的账号数
    dev_accounts = df.groupby("device_id")["uid"].nunique()
    feats["shared_device_accounts"] = (
        df["device_id"].map(dev_accounts).groupby(df["uid"]).max().astype(int))
    return feats
