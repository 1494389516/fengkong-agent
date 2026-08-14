# -*- coding: utf-8 -*-
"""模型登记簿:登记与查询建模实验产出的模型(只登记,不训练)。

定位:模型训练在仓库外(线下/GPU 环境),但"模型全生命周期 SOP"不能等
模型落地才开始 —— 登记簿先补上"模型资产可查询可追溯"这一环:名称/版本/
训练集指纹/指标/状态。登记是元数据记录,与风险处置无关,不走两阶段审批
(与值班确认同级)。
"""
import json
from datetime import datetime, timezone
from typing import Any, Dict, List

from . import tool
from .datasource import data_dir

REGISTRY_FILE = "model_registry.json"


def _path():
    return data_dir() / REGISTRY_FILE


def _load() -> List[Dict]:
    p = _path()
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else []


def _save(items: List[Dict]) -> None:
    _path().write_text(json.dumps(items, ensure_ascii=False, indent=1),
                       encoding="utf-8")


@tool(
    name="model_register",
    description=(
        "登记一个建模实验产出的模型(只登记不训练):名称/版本/训练集指纹/"
        "指标/说明。同名同版本重复登记会被拒绝。训练集指纹取 build_dataset "
        "返回的 manifest.fingerprint。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "模型名"},
            "version": {"type": "string", "description": "版本号"},
            "train_fingerprint": {"type": "string",
                                  "description": "训练集指纹(可空)"},
            "metrics": {"type": "object",
                        "description": "评估指标,如 {\"auc\": 0.92}(可空)"},
            "note": {"type": "string", "description": "训练口径/用途说明(可空)"},
        },
        "required": ["name", "version"],
    },
)
def model_register(name: str, version: str, train_fingerprint: str = "",
                   metrics: Dict[str, Any] = None, note: str = ""):
    items = _load()
    if any(m["name"] == name and m["version"] == version for m in items):
        return {"status": "already_registered", "name": name, "version": version}
    entry = {
        "name": name,
        "version": version,
        "train_fingerprint": train_fingerprint or "",
        "metrics": metrics or {},
        "note": note,
        "registered_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": "candidate",
    }
    items.append(entry)
    _save(items)
    return {"status": "registered", "entry": entry}


@tool(
    name="model_list",
    description=(
        "列出已登记模型:名称/版本/训练集指纹/指标/状态/登记时间。"
        "登记用 model_register。"
    ),
    parameters={"type": "object", "properties": {}},
)
def model_list():
    items = _load()
    return {"count": len(items), "models": items}
