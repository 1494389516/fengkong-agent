# -*- coding: utf-8 -*-
"""实验注册表(P2-3):策略/模型/阈值/prompt/工具裁剪的 A/B 登记与报告。

只登记与管理(control/treatment/population/metrics/决策标准/起止/报告),
不执行实验(执行在真实运行中由人安排)。预设模板:tool_pruning_ab
(TOOL_KEEP_TURNS=2 vs 不裁剪 —— README 已知边界里的待实测项)。
状态:draft -> running -> finished。
"""
import json
from datetime import datetime, timezone
from typing import Dict, List

from . import tool
from .datasource import data_dir

EXPERIMENTS_FILE = "experiments.json"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _path():
    return data_dir() / EXPERIMENTS_FILE


def _load() -> List[Dict]:
    p = _path()
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else []


def _save(items: List[Dict]) -> None:
    from .datasource import atomic_write_json
    atomic_write_json(_path(), items)


@tool(
    name="experiment_register",
    description=(
        "登记实验:kind(可选 tool_pruning_ab 预设模板:TOOL_KEEP_TURNS=2 vs "
        "不裁剪)+ control/treatment 描述 + 人群规则 + 决策标准 + 指标列表。"
        "同名不重复登记,返回 experiment_id。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "实验名"},
            "kind": {"type": "string",
                     "description": "实验类型(可空,预设 tool_pruning_ab)"},
            "control_desc": {"type": "string", "description": "对照组描述"},
            "treatment_desc": {"type": "string", "description": "实验组描述"},
            "population_rule": {"type": "string", "description": "人群规则"},
            "decision_criteria": {"type": "string",
                                  "description": "决策标准(指标差异多大算赢)"},
            "metrics": {"type": "array", "items": {"type": "string"},
                        "description": "指标列表,如 [\"token\",\"accuracy\"]"},
        },
        "required": ["name"],
    },
)
def experiment_register(name: str, kind: str = "", control_desc: str = "",
                        treatment_desc: str = "", population_rule: str = "",
                        decision_criteria: str = "", metrics: List[str] = None):
    items = _load()
    if any(e["name"] == name for e in items):
        return {"error": "实验已存在: %s" % name}
    if kind == "tool_pruning_ab":
        control_desc = control_desc or "TOOL_KEEP_TURNS=2(现状,裁剪旧工具结果)"
        treatment_desc = treatment_desc or "TOOL_KEEP_TURNS=0(不裁剪)"
        metrics = metrics or ["per_case_token", "cache_hit_rate",
                              "answer_quality"]
        decision_criteria = decision_criteria or (
            "token 降幅与缓存命中率变化 + 黄金案例结论一致率不降")
    exp_id = max((e["experiment_id"] for e in items), default=0) + 1
    rec = {"experiment_id": exp_id, "name": name, "kind": kind or "custom",
           "control": control_desc, "treatment": treatment_desc,
           "population_rule": population_rule, "decision_criteria": decision_criteria,
           "metrics": metrics or [], "status": "draft",
           "created_at": _now_iso(), "started_at": None, "finished_at": None,
           "result": None}
    items.append(rec)
    _save(items)
    return {"status": "registered", "experiment_id": exp_id}


@tool(
    name="experiment_start",
    description=("启动实验(状态 running)。已启动/已结束不可重复启动。"),
    parameters={
        "type": "object",
        "properties": {
            "experiment_id": {"type": "integer", "description": "实验 id"},
        },
        "required": ["experiment_id"],
    },
)
def experiment_start(experiment_id: int):
    items = _load()
    for e in items:
        if e["experiment_id"] == experiment_id:
            if e["status"] != "draft":
                return {"error": "状态机拒绝: %s(仅 draft 可启动)"
                                 % e["status"]}
            e["status"] = "running"
            e["started_at"] = _now_iso()
            _save(items)
            return {"status": "running", "experiment_id": experiment_id}
    return {"error": "实验不存在: #%d" % experiment_id}


@tool(
    name="experiment_stop",
    description=(
        "结束实验并记录结果(control/treatment 指标、样本数、数据集指纹)。"
        "结果进报告,是否采纳由人按 decision_criteria 判定。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "experiment_id": {"type": "integer", "description": "实验 id"},
            "result": {"type": "object",
                       "description": "结果,如 {\"control_tokens\": 5000,"
                                      " \"treatment_tokens\": 3000,"
                                      " \"sample_count\": 20}"},
        },
        "required": ["experiment_id", "result"],
    },
)
def experiment_stop(experiment_id: int, result: Dict):
    from .dataset import dataset_fingerprint
    items = _load()
    for e in items:
        if e["experiment_id"] == experiment_id:
            if e["status"] != "running":
                return {"error": "状态机拒绝: %s(仅 running 可结束)"
                                 % e["status"]}
            e["status"] = "finished"
            e["finished_at"] = _now_iso()
            e["result"] = {"data": result,
                           "dataset_fingerprint": dataset_fingerprint()}
            _save(items)
            return {"status": "finished", "experiment_id": experiment_id,
                    "result": e["result"]}
    return {"error": "实验不存在: #%d" % experiment_id}


@tool(
    name="experiment_report",
    description=(
        "实验报告:control/treatment/人群/指标/决策标准/起止时间/结果(含"
        "数据集指纹)。TOOL_KEEP_TURNS A/B 的决策证据在这里沉淀。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "experiment_id": {"type": "integer", "description": "实验 id"},
        },
        "required": ["experiment_id"],
    },
)
def experiment_report(experiment_id: int):
    items = _load()
    for e in items:
        if e["experiment_id"] == experiment_id:
            return {"experiment_id": experiment_id, **e}
    return {"error": "实验不存在: #%d" % experiment_id}
