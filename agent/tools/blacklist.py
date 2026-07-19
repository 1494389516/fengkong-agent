# -*- coding: utf-8 -*-
"""名单查询工具:查当前数据集里的黑/灰名单。"""
from . import tool
from .datasource import load_blacklist


@tool(
    name="blacklist_query",
    description=(
        "查询名单库。传入维度(uid/ip/device_id)和值,返回命中的名单记录。"
        "list 字段为 black(黑名单)或 gray(灰名单),未命中时 hit=false。"
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
    hits = [r for r in load_blacklist() if r["dimension"] == dimension and r["value"] == value]
    return {"hit": bool(hits), "records": hits}
