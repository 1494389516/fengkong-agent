# -*- coding: utf-8 -*-
"""单账号异常监控工具:对一个 uid 的事件流做时间窗扫描 + 关联信号检查。

设计约定:信号必须可解释("窗口内 20 次领券、5 个 IP 轮换"),不给黑盒
异常分 —— 每个信号都能直接写进证据链。返回只含异常窗口,正常窗口不进
上下文(token 友好)。

信号类型:
  burst         窗口内事件数过多
  ip_churn      窗口内 IP 切换过多
  rapid_repeat  窗口内最短间隔过小(机打节奏)
  shared_device 本账号设备被多个账号共用(聚集性/团伙特征)
  blacklist     uid / ip / device 命中黑灰名单
"""
from collections import defaultdict

from . import tool
from .blacklist import blacklist_query
from .datasource import load_events

# 窗口内阈值。样本参照:u_1002 一个 300s 窗口里 20 事件/5 IP/最短 3s,
# u_1001 最密也只有 300s 间隔的 2 个事件,带宽很大,阈值取偏严一侧。
MONITOR_BURST_MIN = 8          # burst:窗口事件数下限
MONITOR_IP_CHURN_MIN = 3       # ip_churn:窗口去重 IP 下限
MONITOR_RAPID_GAP_SECONDS = 5  # rapid_repeat:最短间隔上限……
MONITOR_RAPID_MIN_EVENTS = 3   # ……且窗口内至少这么多事件
SHARED_DEVICE_MIN_ACCOUNTS = 3  # shared_device:设备关联账号数下限


@tool(
    name="account_monitor",
    description=(
        "对单个 uid 做异常监控:按时间窗(默认 300 秒)扫描事件流,报告异常窗口"
        "(burst 高频 / ip_churn IP 轮换 / rapid_repeat 机打节奏),并检查设备共用"
        "(团伙聚集)与黑灰名单关联。返回 signal_types 汇总与逐窗口明细,"
        "只列异常窗口。适合排查'这个账号有没有问题'类问题。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "uid": {"type": "string", "description": "要监控的用户 ID"},
            "window_seconds": {"type": "integer", "description": "时间窗大小(秒),默认 300"},
        },
        "required": ["uid"],
    },
)
def account_monitor(uid: str, window_seconds: int = 300):
    events = load_events()
    mine = sorted((e for e in events if e["uid"] == uid), key=lambda e: e["ts"])
    if not mine:
        return {"uid": uid, "found": False}

    # 1) 时间窗扫描(翻滚窗,锚定首事件)
    t0 = mine[0]["ts"]
    windows = defaultdict(list)
    for e in mine:
        windows[(e["ts"] - t0) // window_seconds].append(e)
    anomalous = []
    signal_types = set()
    for idx in sorted(windows):
        evs = windows[idx]
        ts_list = [e["ts"] for e in evs]
        gaps = [b - a for a, b in zip(ts_list, ts_list[1:])]
        min_gap = min(gaps) if gaps else None
        signals = []
        if len(evs) >= MONITOR_BURST_MIN:
            signals.append("burst")
        if len({e["ip"] for e in evs}) >= MONITOR_IP_CHURN_MIN:
            signals.append("ip_churn")
        if min_gap is not None and min_gap <= MONITOR_RAPID_GAP_SECONDS and len(evs) >= MONITOR_RAPID_MIN_EVENTS:
            signals.append("rapid_repeat")
        if signals:
            signal_types.update(signals)
            anomalous.append({
                "window_start_ts": t0 + idx * window_seconds,
                "event_count": len(evs),
                "distinct_ip": len({e["ip"] for e in evs}),
                "min_gap_seconds": min_gap,
                "types": sorted({e["type"] for e in evs}),
                "signals": signals,
            })

    # 2) 设备共用(跨账号关联,团伙特征)
    shared_devices = []
    for dev in sorted({e["device_id"] for e in mine}):
        users = sorted({e["uid"] for e in events if e["device_id"] == dev})
        if len(users) >= SHARED_DEVICE_MIN_ACCOUNTS:
            signal_types.add("shared_device")
            shared_devices.append({"device_id": dev, "account_count": len(users), "accounts": users})

    # 3) 黑灰名单关联(uid + 该账号用过的全部 ip/设备)
    blacklist_signals = []
    dims = [("uid", uid)]
    dims += [("ip", ip) for ip in sorted({e["ip"] for e in mine})]
    dims += [("device_id", d) for d in sorted({e["device_id"] for e in mine})]
    for dim, val in dims:
        for rec in blacklist_query(dim, val)["records"]:
            signal_types.add("blacklist")
            blacklist_signals.append("%s=%s 命中%s名单: %s" % (dim, val, rec["list"], rec["reason"]))

    return {
        "uid": uid,
        "found": True,
        "window_seconds": window_seconds,
        "windows_total": len(windows),
        "anomalous_windows": anomalous,
        "shared_devices": shared_devices,
        "blacklist_signals": blacklist_signals,
        "signal_types": sorted(signal_types),
    }
