# -*- coding: utf-8 -*-
"""反馈管道(P2-2):申诉 / 对账差异 / 事故 / 标签冲突 统一聚合 -> 候选。

形成:Decision -> Appeal/Incident -> Label correction -> Dataset refresh
-> Model/Strategy evaluation -> Candidate。
铁律:自动产生 candidate 可以,自动进入 production 不行 —— 本工具只聚合
与建议,不写任何生产状态。
"""
import json
from typing import Dict, List

from . import tool
from .datasource import data_dir, load_appeals

OVERRIDES_FILE = "analyst_overrides.jsonl"


def record_override(rec: Dict) -> None:
    """分析师否决/纠偏落盘(Ojuri: reviewer overrule → 训练信号)。
    只追加,不改标签、不进生产。"""
    p = data_dir() / OVERRIDES_FILE
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:  # noqa: BLE001 回灌失败不掀翻审批
        pass


def _load_overrides() -> List[Dict]:
    p = data_dir() / OVERRIDES_FILE
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


@tool(
    name="feedback_pipeline",
    description=(
        "聚合反馈信号(待处理申诉 / 未销差异工单 / 未结案事故 / 规则-标签"
        "冲突 / 分析师否决回灌)生成治理候选清单。自动产出 candidate 可以,"
        "自动进入生产不行 —— 候选必须人审后走正规审批链。"
    ),
    parameters={"type": "object", "properties": {}},
)
def feedback_pipeline():
    from .incidents import _load as _inc_load
    from .label_quality_proxy import label_conflicts
    from .reconcile import _load_queue as _mq_load

    appeals = [a for a in load_appeals() if a.get("status") == "pending"]
    mismatches = [m for m in _mq_load() if m.get("status") == "open"]
    incidents = [i for i in _inc_load() if i.get("status") == "open"]
    conflicts = label_conflicts()
    overrides = [o for o in _load_overrides() if o.get("status") != "consumed"]
    candidates = []
    for c in conflicts:
        candidates.append({"kind": "label_review",
                           "uid": c["uid"], "type": c["type"],
                           "evidence": "规则-标签冲突",
                           "action": "按标注 SOP 复核标签,勿自动改"})
    for i in incidents:
        candidates.append({"kind": "incident", "incident_id": i["incident_id"],
                           "type": i["incident_type"],
                           "action": "incident_resolve 前先定位根因"})
    for m in mismatches[:5]:
        candidates.append({"kind": "mismatch", "key": m["key"],
                           "action": "mismatch_resolve 销单(写根因分类)"})
    if appeals:
        candidates.append({"kind": "appeal",
                           "count": len(appeals),
                           "action": "appeal_review 核查后决议"})
    if overrides:
        candidates.append({"kind": "analyst_override",
                           "count": len(overrides),
                           "action": "否决/纠偏已回灌,复核是否进建模样本(勿自动改标签)"})
    return {
        "summary": {
            "pending_appeals": len(appeals),
            "open_mismatches": len(mismatches),
            "open_incidents": len(incidents),
            "label_conflicts": len(conflicts),
            "analyst_overrides": len(overrides),
        },
        "candidates": candidates,
        "note": "候选仅供人审;进入生产必须走审批链(candidate -> 评估 -> 审批)",
    }
