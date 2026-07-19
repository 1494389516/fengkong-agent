# -*- coding: utf-8 -*-
"""名单查询工具:查 data/blacklist.json 里的黑/灰名单。"""
import json
from pathlib import Path

from . import tool

DATA = Path(__file__).resolve().parent.parent.parent / "data" / "blacklist.json"


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
    records = json.loads(DATA.read_text(encoding="utf-8"))
    hits = [r for r in records if r["dimension"] == dimension and r["value"] == value]
    return {"hit": bool(hits), "records": hits}
