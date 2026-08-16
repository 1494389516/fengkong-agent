# -*- coding: utf-8 -*-
"""特征查询工具:featurelib 统一特征层的薄封装。

特征计算全部在 featurelib(单一事实源),本文件只负责注册工具 schema
和补充反向基数摘要。骨架阶段数据来自本地 JSON,换真实数仓只改 datasource。
"""
from typing import Optional

from . import tool
from .featurelib import account_features, accounts_per, behavior_paths, percentile_rank


@tool(
    name="feature_stats",
    description=(
        "计算某个 uid 的行为特征:事件数、去重 IP/设备、事件类型分布、最短间隔、"
        "订单统计(次数/最大/累计金额)、反向基数(该账号的设备/IP 最多被几个账号"
        "共用,>=3 是团伙信号)、行为路径 behavior(会话级序列签名:套现 "
        "login→券×N→单 / 盗号登录后直奔 order / bot 纯券流),以及人群百分位 "
        "population_percentile(证据链引用:min_gap_seconds 百分位低 = 比几乎所有账号都快)。"
        "as_of_ts 取证时点(只统计该时刻之前的事件,评估历史事件时必传,防止"
        "偷看未来);window_seconds 时间窗(只统计最近 N 秒,行为模式类判断用)。"
        "两者都不传 = 全历史。"
        "account_profile 已判目标 uid 不存在时不要再调。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "uid": {"type": "string", "description": "用户 ID"},
            "as_of_ts": {"type": "number", "description": "取证时点(unix 秒),只统计此前事件"},
            "window_seconds": {"type": "integer", "description": "时间窗大小(秒)"},
        },
        "required": ["uid"],
    },
)
def feature_stats(uid: str, as_of_ts: Optional[float] = None,
                  window_seconds: Optional[int] = None):
    r = account_features(uid, as_of_ts, window_seconds)
    if r["found"]:
        r["accounts_per_device_max"] = max(
            (accounts_per("device_id", d, as_of_ts)["count"] for d in r["devices"]), default=0)
        r["accounts_per_ip_max"] = max(
            (accounts_per("ip", ip, as_of_ts)["count"] for ip in r["ips"]), default=0)
        # 行为路径:会话级序列签名(套现 login→券×N→单 / 盗号直奔 order / bot 纯券流)
        bp = behavior_paths(uid, as_of_ts)
        r["behavior"] = {
            "sessions": bp["sessions"],
            "top_paths": bp["top_paths"][:3],
            "login_to_order_min_seconds": bp["login_to_order_min_seconds"],
        }
        # 人群百分位:<= 该值的账号占比。min_gap_seconds 百分位低 = 比几乎所有人都快。
        r["population_percentile"] = {
            f: percentile_rank(f, r[f])
            for f in ("event_count", "distinct_ip", "coupon_claims",
                      "min_gap_seconds", "order_amount_max")
            if r.get(f) is not None
        }
        return r
    r["next_action"] = "stop"
    r["stop_reason"] = (
        "该 uid 无事件,特征为空。若 account_profile 已判不存在则停止,"
        "不要再拆监控/体检。")
    return r
