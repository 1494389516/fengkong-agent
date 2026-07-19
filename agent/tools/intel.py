# -*- coding: utf-8 -*-
"""IP 情报工具:网段类型 / 地理位置 / 风险等级,以及地理跳变检测。

为什么需要:distinct_ip 只是"数量",情报给的是"质量" —— 同样 3 个 IP,
3 个家宽基站和 3 个机房代理是两个物种。地理跳变(相邻事件的 IP 地理距离
除以时间差 = 移动速度,超过民航速度即物理不可能)是经典盗号信号。

秒拨/代理段(lat 为空)不参与跳变计算:它们的地理位置本身不可信,
用不可信坐标算出来的"跳变"是噪音不是信号。
"""
from math import asin, cos, radians, sin, sqrt
from typing import Dict, List, Optional

from . import tool
from .datasource import load_ip_intel

MIN_JUMP_KM = 50  # 同城基站切换不算跳变


def _segment(ip: str) -> str:
    return ".".join(ip.split(".")[:3])


def ip_info(ip: str) -> Dict:
    seg = _segment(ip)
    info = load_ip_intel().get(seg)
    if not info:
        return {"ip": ip, "segment": seg, "type": "unknown", "risk": "unknown"}
    return {"ip": ip, "segment": seg, **info}


def ip_type_summary(ips) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for ip in ips:
        t = ip_info(ip)["type"]
        out[t] = out.get(t, 0) + 1
    return out


def _haversine_km(a: Dict, b: Dict) -> float:
    la1, lo1, la2, lo2 = map(radians, (a["lat"], a["lon"], b["lat"], b["lon"]))
    h = sin((la2 - la1) / 2) ** 2 + cos(la1) * cos(la2) * sin((lo2 - lo1) / 2) ** 2
    return 6371 * 2 * asin(sqrt(h))


def geo_jumps(events_sorted: List[Dict], speed_limit_kmh: float) -> List[Dict]:
    """按时间序扫描相邻事件,报告物理不可能的移动。events 需已按 ts 升序。"""
    jumps = []
    prev: Optional[tuple] = None
    for e in events_sorted:
        info = ip_info(e["ip"])
        if info.get("lat") is None:
            continue  # 未知段/秒拨段坐标不可信,跳过
        if prev is not None:
            dist = _haversine_km(prev[1], info)
            dt = max(e["ts"] - prev[0]["ts"], 1)
            speed = dist / (dt / 3600)
            if dist >= MIN_JUMP_KM and speed > speed_limit_kmh:
                jumps.append({
                    "from_ip": prev[0]["ip"], "from_city": prev[1].get("city"),
                    "to_ip": e["ip"], "to_city": info.get("city"),
                    "km": round(dist), "minutes": round(dt / 60),
                    "speed_kmh": round(speed),
                })
        prev = (e, info)
    return jumps


@tool(
    name="ip_intel",
    description=(
        "查询 IP 情报:网段类型(residential 家宽 / mobile 基站 / idc 机房 / "
        "proxy 代理秒拨 / unknown)、运营商、城市与经纬度、风险等级。"
        "登录/下单出现 idc 或 proxy 段本身就是强风险信号;"
        "同样的去重 IP 数,家宽和机房是两个物种。"
    ),
    parameters={
        "type": "object",
        "properties": {"ip": {"type": "string", "description": "要查询的 IP"}},
        "required": ["ip"],
    },
)
def ip_intel(ip: str):
    return ip_info(ip)
