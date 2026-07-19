# -*- coding: utf-8 -*-
"""特征计算工具:对 data/events_sample.json 的事件流做聚合统计。

骨架阶段用本地 JSON 模拟事件表;后续可替换为真实数仓/日志查询,
只要保持返回结构不变,上层 agent 无感知。
"""
import json
from collections import Counter
from pathlib import Path

from . import tool

DATA = Path(__file__).resolve().parent.parent.parent / "data" / "events_sample.json"


@tool(
    name="feature_stats",
    description=(
        "计算某个 uid 在事件样本里的行为特征:事件总数、去重 IP 数、去重设备数、"
        "事件类型分布、最短事件间隔(秒)。用于判断机器行为/多账号/聚集性特征。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "uid": {"type": "string", "description": "用户 ID"},
        },
        "required": ["uid"],
    },
)
def feature_stats(uid: str):
    events = [e for e in json.loads(DATA.read_text(encoding="utf-8")) if e["uid"] == uid]
    if not events:
        return {"uid": uid, "found": False}
    ts = sorted(e["ts"] for e in events)
    gaps = [b - a for a, b in zip(ts, ts[1:])]
    return {
        "uid": uid,
        "found": True,
        "event_count": len(events),
        "distinct_ip": len({e["ip"] for e in events}),
        "distinct_device": len({e["device_id"] for e in events}),
        "event_types": dict(Counter(e["type"] for e in events)),
        "min_gap_seconds": min(gaps) if gaps else None,
        "ips": sorted({e["ip"] for e in events}),
        "devices": sorted({e["device_id"] for e in events}),
    }
