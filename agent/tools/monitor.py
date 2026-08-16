# -*- coding: utf-8 -*-
"""单账号异常监控工具:对一个 uid 的事件流做时间窗扫描 + 关联信号检查。

设计约定:信号必须可解释("窗口内 20 次领券、5 个 IP 轮换"),不给黑盒
异常分 —— 每个信号都能直接写进证据链。返回只含异常窗口,正常窗口不进
上下文(token 友好)。

信号类型:
  burst             窗口内事件数过多
  ip_churn          窗口内 IP 切换过多
  rapid_repeat      窗口内最短间隔过小(机打节奏)
  shared_device     本账号设备被多个账号共用(聚集性/团伙特征)
  blacklist         uid / ip / device 命中黑灰名单
  self_new_device   近窗出现历史未见设备(自身基线,盗号信号)
  self_amount_spike 近窗最大订单较自身历史突增(自身基线,销赃信号)
  geo_jump          相邻事件地理跳变(移动速度超过民航速度,物理不可能)
  risky_device      设备指纹命中(模拟器 / root / hook 注入)

自身基线带账龄门槛(policy.self_min_history_events):历史太浅的账号不启用
—— 否则盗号者潜伏几天"养"出一条正常自身基线就能骗过它,新号也会误报。
阈值全部经 policy.active_policy() 解析(监控是"现在看",取当前最新版)。
"""
from collections import defaultdict

from . import tool
from .blacklist import blacklist_query
from .datasource import load_events
from .intel import device_risk_flags, geo_jumps
from .policy import active_policy


@tool(
    name="account_monitor",
    description=(
        "对单个 uid 做异常监控:按时间窗(默认 300 秒)扫描事件流,报告异常窗口"
        "(burst 高频 / ip_churn IP 轮换 / rapid_repeat 机打节奏),并检查设备共用"
        "(团伙聚集)与黑灰名单关联。返回 signal_types 汇总与逐窗口明细,"
        "只列异常窗口。适合排查'这个账号有没有问题'类问题。"
        "account_profile 已判目标 uid 不存在时不要再调。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "uid": {"type": "string", "description": "要监控的用户 ID"},
            "window_seconds": {"type": "integer", "minimum": 1,
                               "description": "时间窗大小(秒),默认 300"},
        },
        "required": ["uid"],
    },
)
def account_monitor(uid: str, window_seconds: int = 300):
    # 0/负值窗口会在翻滚窗分桶时除零;回落默认窗口而非报错 —— 否则连与窗口
    # 无关的名单/设备指纹/地理跳变信号也会随异常一起丢失(schema minimum
    # 不被模型可靠遵守,运行时兜底才是真防线)
    if not window_seconds or window_seconds <= 0:
        window_seconds = 300
    p = active_policy()  # 入口取一次快照,整个函数同一份口径
    events = load_events()
    mine = sorted((e for e in events if e["uid"] == uid), key=lambda e: e["ts"])
    if not mine:
        return {"uid": uid, "found": False, "next_action": "stop",
                "stop_reason": "该 uid 无事件可监控。若 account_profile 已判不存在则停止。"}

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
        if len(evs) >= p["monitor_burst_min"]:
            signals.append("burst")
        if len({e["ip"] for e in evs}) >= p["monitor_ip_churn_min"]:
            signals.append("ip_churn")
        if (min_gap is not None and min_gap <= p["monitor_rapid_gap_seconds"]
                and len(evs) >= p["monitor_rapid_min_events"]):
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
        if len(users) >= p["shared_device_min_accounts"]:
            signal_types.add("shared_device")
            shared_devices.append({"device_id": dev, "account_count": len(users), "accounts": users})

    # 2.5) 自身基线:近窗行为 vs 自己的历史(账龄门槛见模块 docstring)
    self_signals = []
    recent_start = mine[-1]["ts"] - p["self_recent_window_seconds"]
    prior = [e for e in mine if e["ts"] < recent_start]
    recent = [e for e in mine if e["ts"] >= recent_start]
    if len(prior) >= p["self_min_history_events"] and recent:
        new_devs = sorted({e["device_id"] for e in recent} - {e["device_id"] for e in prior})
        if new_devs:
            signal_types.add("self_new_device")
            self_signals.append("近 %d 小时出现历史未见设备: %s" % (
                p["self_recent_window_seconds"] // 3600, ", ".join(new_devs)))
        prior_amt = [e["amount"] for e in prior if e.get("amount") is not None]
        recent_amt = [e["amount"] for e in recent if e.get("amount") is not None]
        if prior_amt and recent_amt:
            if (max(recent_amt) >= p["self_amount_spike_ratio"] * max(prior_amt)
                    and max(recent_amt) >= p["self_amount_floor"]):
                signal_types.add("self_amount_spike")
                self_signals.append("近窗最大订单 %.2f,为自身历史最大 %.2f 的 %.1f 倍" % (
                    max(recent_amt), max(prior_amt), max(recent_amt) / max(prior_amt)))

    # 2.7) 地理跳变(经典盗号信号,情报缺失的网段不参与)
    jumps = geo_jumps(mine, p["geo_jump_speed_kmh"])
    if jumps:
        signal_types.add("geo_jump")

    # 2.8) 设备指纹:模拟器 / root / hook —— 设备层的"出生缺陷",指纹 SDK 采集
    risky_devices = []
    for dev in sorted({e["device_id"] for e in mine}):
        flags = device_risk_flags(dev)
        if flags:
            signal_types.add("risky_device")
            risky_devices.append("%s: %s" % (dev, "、".join(flags)))

    # 3) 名单关联(uid + 该账号用过的全部 ip/设备):黑/灰是风险信号;
    #    白名单是误伤抑制标注,单列不进 signal_types(它不是异常)
    blacklist_signals = []
    whitelist_notes = []
    dims = [("uid", uid)]
    dims += [("ip", ip) for ip in sorted({e["ip"] for e in mine})]
    dims += [("device_id", d) for d in sorted({e["device_id"] for e in mine})]
    for dim, val in dims:
        for rec in blacklist_query(dim, val)["records"]:
            if rec.get("expired"):
                continue
            if rec["list"] == "white":
                whitelist_notes.append("%s=%s 在白名单: %s%s" % (
                    dim, val, rec["reason"],
                    "(有效期至 %s)" % rec["expires_at"] if rec.get("expires_at") else ""))
            else:
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
        **({"whitelist_notes": whitelist_notes} if whitelist_notes else {}),
        "self_baseline_signals": self_signals,
        "geo_jumps": jumps,
        "risky_devices": risky_devices,
        "signal_types": sorted(signal_types),
        "policy_version": p["_version"],
    }
