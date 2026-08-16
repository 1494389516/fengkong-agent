# -*- coding: utf-8 -*-
"""名单查询工具:黑 / 灰 / 白三色名单的统一存取。

三色语义(风控名单的正确打开方式):
  black  人工确认的强证据(盗号工单、代理池)—— R001 直接 reject。
  gray   嫌疑观察(设备指纹可疑等)—— R001 给 review 留人工兜底。
  white  误伤抑制:申诉通过的老客、内部测试号、合作方出口 —— 行为规则
         (R002~R005)对其失效,但**硬证据只降档不豁免**(R001 黑名单、
         R006 设备指纹的 reject 降为 review):白名单账号被盗/被收买时
         仍有人工闸门,不是免死金牌。白名单本身是攻击面,进出必须走
         两阶段审批,并建议带 expires_at 有效期。

expires_at(可选,"YYYY-MM-DD"):到期后该记录视为不存在。判定按**事件
时点**比较(回放历史事件用当时的有效性,不是现在的)—— 与特征/策略的
point-in-time 口径一致。added_at 目前不参与回放过滤(全名单库的已知简化:
名单被视为"从来如此",接真实名单服务时应换成带版本的快照查询)。
"""
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional

from . import tool
from .datasource import load_blacklist

VALID_LISTS = ("black", "gray", "white")


def _expired(record: Dict, as_of_ts: Optional[float]) -> bool:
    exp = record.get("expires_at")
    if not exp:
        return False
    try:
        exp_ts = datetime.strptime(exp, "%Y-%m-%d").replace(
            tzinfo=timezone.utc).timestamp() + 86400  # 到期日当天仍有效
    except ValueError:
        return False  # 格式坏了当永久,宁可多抑制也不静默丢记录
    return (as_of_ts if as_of_ts is not None else time.time()) >= exp_ts


def active_records(dimension: str, value: str, as_of_ts: Optional[float] = None,
                   lists: Optional[tuple] = None) -> List[Dict]:
    """未过期的名单记录(规则引擎口径)。lists 过滤名单颜色,None=全部。"""
    return [r for r in load_blacklist()
            if r["dimension"] == dimension and r["value"] == value
            and not _expired(r, as_of_ts)
            and (lists is None or r["list"] in lists)]


@tool(
    name="blacklist_query",
    description=(
        "查询名单库。传入维度(uid/ip/device_id)和值,返回命中的名单记录。"
        "list 字段:black(黑,强证据硬拦)/ gray(灰,嫌疑观察)/ white(白,"
        "误伤抑制:行为规则失效、硬证据降档 review,只降档不豁免)。带 expires_at 的"
        "记录到期即失效(expired=true 标注)。未命中时 hit=false。"
        "查询不是变更。移除须点名后走待审批,回答用「须 /approve」,不要写「已生效」。"
        "account_profile 已判目标 uid 不存在时不要再调本工具核同一 uid。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "dimension": {
                "type": "string",
                "enum": ["uid", "ip", "device_id"],
                "description": "查询维度",
            },
            "value": {"type": "string", "description": "要查询的值"},
        },
        "required": ["dimension", "value"],
    },
)
def blacklist_query(dimension: str, value: str):
    hits = [dict(r, **({"expired": True} if _expired(r, None) else {}))
            for r in load_blacklist()
            if r["dimension"] == dimension and r["value"] == value]
    out = {"hit": any(not h.get("expired") for h in hits), "records": hits,
           "speak": "查询不是变更。移除须点名后走待审批,回答用「须 /approve」,"
                    "不要写「已生效」。"}
    if any(not h.get("expired") and h.get("list") == "white" for h in hits):
        out["speak"] += " 白名单只降档不豁免,回答不要写「免检」。"
    return out
