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
import statistics
from collections import Counter
from typing import Dict, List, Optional, Tuple

from .datasource import data_dir, load_events


_uid_index_cache: Dict[str, tuple] = {}


def _events_by_uid() -> Dict[str, List[Dict]]:
    """按 uid 分组的事件索引,按数据集 (路径, mtime) 缓存(_dataset_key 见下)。
    回测/巡检要对每个账号取事件:没有索引时每次都全量扫 events,N 账号 × E 事件
    退化成 O(N·E)(大样本上量到过 6000+ 次全表扫描);建一次索引后账号取数只碰
    自己那一撮。索引条目从不外泄(返回都是新列表),不会被调用方就地改写。"""
    key = _dataset_key()
    hit = _uid_index_cache.get("idx")
    if hit and hit[0] == key:
        return hit[1]
    idx: Dict[str, List[Dict]] = {}
    for e in load_events():
        idx.setdefault(e["uid"], []).append(e)
    _uid_index_cache["idx"] = (key, idx)
    return idx


def _account_events(uid: str, as_of_ts: Optional[float] = None) -> List[Dict]:
    evs = _events_by_uid().get(uid, ())
    if as_of_ts is None:
        return list(evs)
    return [e for e in evs if e["ts"] < as_of_ts]


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
    # 领券专用间隔:R002 问的是"领券多快",全事件流的 min_gap 会把
    # login→order 的手快当成刷券证据(实锤误伤过正常账号)
    coupon_ts = sorted(e["ts"] for e in evs if e["type"] == "coupon_claim")
    coupon_gaps = [b - a for a, b in zip(coupon_ts, coupon_ts[1:])]
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
        "coupon_min_gap_seconds": min(coupon_gaps) if coupon_gaps else None,
        "span_seconds": ts[-1] - ts[0],
        "ips": sorted({e["ip"] for e in evs}),
        "devices": sorted({e["device_id"] for e in evs}),
    }


def behavior_paths(uid: str, as_of_ts: Optional[float] = None,
                   session_gap_seconds: int = 1800) -> Dict:
    """行为路径(序列特征):事件流按会话切分(相邻间隔超过 session_gap 断开),
    每个会话压缩成路径串(连续同类型折叠为 类型×N)。路径是行为的"语法",
    各类欺诈有签名:
      正常购物   多会话分散,login→order / login→coupon_claim 混合
      套现       login→coupon_claim×N→order(领券后立即小额下单)
      盗号       login→order 直奔下单,无任何铺垫(login_to_order 间隔极短)
      刷券 bot   无 login 的纯 coupon_claim×N 流
    """
    evs = sorted(_account_events(uid, as_of_ts), key=lambda e: e["ts"])
    if not evs:
        return {"uid": uid, "found": False}
    sessions: List[List[Dict]] = [[evs[0]]]
    for prev, e in zip(evs, evs[1:]):
        if e["ts"] - prev["ts"] > session_gap_seconds:
            sessions.append([])
        sessions[-1].append(e)

    def compress(sess: List[Dict]) -> str:
        parts: List[List] = []
        for e in sess:
            if parts and parts[-1][0] == e["type"]:
                parts[-1][1] += 1
            else:
                parts.append([e["type"], 1])
        return "→".join(t if n == 1 else "%s×%d" % (t, n) for t, n in parts)

    path_counts = Counter(compress(s) for s in sessions)
    # login→order 最短间隔:盗号"直奔下单"的量化(登录多久后就下单)
    l2o = None
    last_login = None
    for e in evs:
        if e["type"] == "login":
            last_login = e["ts"]
        elif e["type"] == "order" and last_login is not None:
            gap = e["ts"] - last_login
            l2o = gap if l2o is None else min(l2o, gap)
    return {
        "uid": uid,
        "found": True,
        "sessions": len(sessions),
        "session_gap_seconds": session_gap_seconds,
        "top_paths": [{"path": p, "count": c} for p, c in path_counts.most_common(5)],
        "login_to_order_min_seconds": l2o,
    }


def accounts_per(dimension: str, value: str, as_of_ts: Optional[float] = None) -> Dict:
    """反向基数特征:一个 ip / device_id 上出现过多少账号(含查询账号自身)。
    真实电商风控里最强的单特征之一 —— 资源被多账号共用是团伙的直接证据。"""
    assert dimension in ("ip", "device_id")
    accounts = sorted({e["uid"] for e in load_events()
                       if e[dimension] == value and (as_of_ts is None or e["ts"] < as_of_ts)})
    return {"dimension": dimension, "value": value,
            "count": len(accounts), "accounts": accounts}


# ---------------------------------------------------------------------------
# 人群基线:全量账号特征分布的稳健统计。
# 用中位数/分位数而非均值/标准差 —— 欺诈是少数派,拖不动分位数;
# 均值和方差会被 bot 的极端值(20 次 3 秒间隔)直接拖飞。
# 两个用途:① 阈值推导的地基(threshold_calibrate);② 证据链定量化
# (feature_stats 的百分位标注:"间隔 3 秒,低于人群 P17" 比 "间隔 3 秒" 有力)。
# 纯 Python 实现(statistics),规则/监控路径保持 pandas-free。
# ---------------------------------------------------------------------------

BASELINE_FEATURES = ("event_count", "distinct_ip", "distinct_device",
                     "coupon_claims", "min_gap_seconds", "order_amount_max")

_pop_cache: Dict[str, Tuple] = {}


def _dataset_key() -> Tuple[str, int]:
    p = data_dir() / "events_sample.json"
    return (str(p), p.stat().st_mtime_ns)


def _all_account_features() -> List[Dict]:
    """全量账号的特征 dict 列表,按数据集 (路径, mtime) 缓存。"""
    key = _dataset_key()
    hit = _pop_cache.get("feats")
    if hit and hit[0] == key:
        return hit[1]
    uids = sorted({e["uid"] for e in load_events()})
    feats = [account_features(u) for u in uids]
    _pop_cache["feats"] = (key, feats)
    return feats


def feature_values(feature: str) -> List[float]:
    """某特征的全量账号取值(升序,跳过缺失)。"""
    return sorted(v for f in _all_account_features()
                  if (v := f.get(feature)) is not None)


def population_baseline() -> Dict[str, Dict[str, float]]:
    """人群基线:各特征的稳健分位数与 MAD。样本量太小时(n<2)该特征跳过,
    n 随结果返回 —— 小样本上的分位数没有推导价值,调用方要看着 n 用。

    deciles 是等频十分箱切点(9 个数):策略快照带上它之后,漂移检查可以做
    分布级 PSI 比对(drift.psi_against_edges),而不只盯 P99 单点 —— 中段的
    整体位移("温水式"养基线)只有分布比较才看得见。存切点不存原始样本,
    快照体积不变量级。切点刻意不去重:重复切点的重数就是尖峰质量信息,
    psi_against_edges 按重数还原 expected;在这里去重会让尖峰特征自比虚高
    (统计核心 eval 层钉着)。"""
    out = {}
    for feat in BASELINE_FEATURES:
        vals = feature_values(feat)
        if len(vals) < 2:
            continue
        qs = statistics.quantiles(vals, n=1000, method="inclusive")
        p50 = qs[499]
        out[feat] = {
            "n": len(vals),
            "p50": round(p50, 2),
            "p90": round(qs[899], 2),
            "p99": round(qs[989], 2),
            "p999": round(qs[998], 2),
            "mad": round(statistics.median(abs(v - p50) for v in vals), 2),
            "deciles": [round(q, 4) for q in
                        statistics.quantiles(vals, n=10, method="inclusive")],
        }
    return out


def percentile_rank(feature: str, value: float) -> Optional[float]:
    """value 在人群中的百分位(<= value 的账号占比)。无数据返回 None。"""
    vals = feature_values(feature)
    if not vals:
        return None
    return round(sum(1 for v in vals if v <= value) / len(vals), 4)


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
