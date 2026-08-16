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
from .datasource import load_device_intel, load_ip_intel

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
                    "from_ts": prev[0]["ts"],
                    "to_ip": e["ip"], "to_city": info.get("city"), "to_ts": e["ts"],
                    "km": round(dist), "minutes": round(dt / 60),
                    "speed_kmh": round(speed),
                })
        prev = (e, info)
    return jumps


def device_info(device_id: str) -> Dict:
    info = load_device_intel().get(device_id)
    if not info:
        return {"device_id": device_id, "known": False, "risk": "unknown"}
    return {"device_id": device_id, "known": True, **info}


def device_risk_flags(device_id: str) -> List[str]:
    """设备的风险标记列表(空 = 干净或未知)。给监控信号与图表用。"""
    info = device_info(device_id)
    flags = []
    if info.get("is_emulator"):
        flags.append("模拟器" + ("(%s)" % info["emulator_brand"] if info.get("emulator_brand") else ""))
    if info.get("is_rooted"):
        flags.append("root")
    if info.get("hook_detected"):
        flags.append("hook")
    return flags


def device_type_summary(devices) -> Dict[str, int]:
    """设备质量分布:模拟器 / root|hook / 正常 / 未知。和 IP 类型同款语义 ——
    设备数是数量,指纹是物种。"""
    out: Dict[str, int] = {}
    for d in devices:
        info = device_info(d)
        if not info.get("known"):
            key = "未知"
        elif info.get("is_emulator"):
            key = "模拟器"
        elif info.get("is_rooted") or info.get("hook_detected"):
            key = "root/hook"
        else:
            key = "正常"
        out[key] = out.get(key, 0) + 1
    return out


@tool(
    name="device_intel",
    description=(
        "查询单台设备指纹:是否模拟器(含品牌)、root/越狱、hook 注入框架"
        "(Xposed/Frida)、原始采集信号(传感器无数据/电池恒 100%/x86 架构等)、"
        "风险档。graph_relations 的 device_flags / account_profile 已含标记时"
        "不要逐台补调;只对档案缺字段的一台补一次。"
        "模拟器+老安卓+多账号共用是设备农场三件套;交易设备上的 root+hook"
        "是改机/自动化直接证据。"
    ),
    parameters={
        "type": "object",
        "properties": {"device_id": {"type": "string", "description": "设备 ID"}},
        "required": ["device_id"],
    },
)
def device_intel(device_id: str):
    return device_info(device_id)


@tool(
    name="ip_intel",
    description=(
        "查询单个 IP 情报:网段类型(residential 家宽 / mobile 基站 / idc 机房 / "
        "proxy 代理秒拨 / unknown)、运营商、城市与经纬度、风险等级。"
        "图谱 weak_ips 或档案 IP 类型分布已够用时不要对每个 IP 补调;"
        "登录/下单出现 idc 或 proxy 段本身就是强风险信号。"
    ),
    parameters={
        "type": "object",
        "properties": {"ip": {"type": "string", "description": "要查询的 IP"}},
        "required": ["ip"],
    },
)
def ip_intel(ip: str):
    return ip_info(ip)
