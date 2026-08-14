# -*- coding: utf-8 -*-
"""模型生命周期登记簿:从"登记"到"上线/回滚"的完整状态机(只管理,不训练)。

状态机(每条转移都有门禁,门禁在代码层,不在 prompt):
  candidate --(自动)--> shadow --(评估门禁)--> challenger --(人审批)--> champion
  champion --(审批+audit)--> rollback | deprecated(被新 champion 顶替)

铁律:
  - champion 同时只能有一个(新 champion 上线自动把旧 champion 置 deprecated);
  - 模型必须绑定 train_fingerprint + feature_catalog_version(feature semantics);
  - model_eval 只在"评估数据集指纹 == 训练指纹"时有效 —— 换个数据集评出来的
    指标不能冒充训练集表现;
  - shadow -> challenger 必须已过评估门禁(metrics 存在且指纹匹配);
  - challenger -> champion 必须走 pending 审批(actions.decide 批准后才落盘),
    审批 id 进记录(approval_id),rollback 同样走审批并写审计;
  - 不允许重复 promote(已在目标状态或更远状态 = 拒绝);
  - 非法 rollback(非 champion 回滚)= 拒绝。

登记簿是元数据,写的是 data/model_registry.json(运行时文件,gitignored)。
"""
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from . import tool
from .datasource import data_dir, load_labels, pending_actions_path

REGISTRY_FILE = "model_registry.json"

STATES = ("candidate", "shadow", "challenger", "champion", "deprecated", "rollback")
_RANK = {s: i for i, s in enumerate(STATES)}
# 允许的前向转移:目标必须严格在候选之后、且跳级受限(见 _can_promote)
_ALLOWED_FORWARD = {
    "candidate": ("shadow",),       # 自动
    "shadow": ("challenger",),      # 评估门禁
    "challenger": ("champion",),    # 人审批
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _feature_catalog_version() -> str:
    """feature semantics 指纹:目录变了版本必变,模型记录与之绑定。"""
    from .featurelib import FEATURE_CATALOG
    blob = json.dumps(FEATURE_CATALOG, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def _path():
    return data_dir() / REGISTRY_FILE


def _load() -> List[Dict]:
    p = _path()
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else []


def _save(items: List[Dict]) -> None:
    _path().write_text(json.dumps(items, ensure_ascii=False, indent=1),
                       encoding="utf-8")


def _find(items: List[Dict], name: str, version: str) -> Optional[Dict]:
    for m in items:
        if m["name"] == name and m["version"] == version:
            return m
    return None


def _pending() -> List[Dict]:
    p = pending_actions_path()
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else []


def _save_pending(items: List[Dict]) -> None:
    pending_actions_path().write_text(
        json.dumps(items, ensure_ascii=False, indent=1), encoding="utf-8")


def _submit_pending(entry: Dict) -> int:
    pending = _pending()
    action_id = max((a["action_id"] for a in pending), default=0) + 1
    pending.append({"action_id": action_id, **entry})
    _save_pending(pending)
    return action_id


@tool(
    name="model_register",
    description=(
        "登记一个建模实验产出的模型(只登记不训练):名称/版本/训练集指纹/"
        "指标/说明。同名同版本重复登记会被拒绝。train_fingerprint 取 "
        "build_dataset 的 manifest.fingerprint;feature_catalog_version 缺省"
        "自动取当前特征目录指纹(特征语义改了记录就失效)。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "模型名"},
            "version": {"type": "string", "description": "版本号"},
            "train_fingerprint": {"type": "string", "description": "训练集指纹"},
            "feature_catalog_version": {"type": "string",
                                        "description": "特征目录指纹(可空,自动取)"},
            "metrics": {"type": "object", "description": "初始指标(可空)"},
            "note": {"type": "string", "description": "训练口径/用途说明(可空)"},
        },
        "required": ["name", "version", "train_fingerprint"],
    },
)
def model_register(name: str, version: str, train_fingerprint: str = "",
                   feature_catalog_version: str = "", metrics: Dict = None,
                   note: str = ""):
    items = _load()
    if _find(items, name, version):
        return {"status": "already_registered", "name": name, "version": version}
    entry = {
        "name": name,
        "version": version,
        "train_fingerprint": train_fingerprint,
        "feature_catalog_version": (feature_catalog_version
                                    or _feature_catalog_version()),
        "metrics": metrics or {},
        "created_at": _now_iso(),
        "status": "candidate",
        "approval_id": None,
        "deployed_at": None,
        "retired_at": None,
        "note": note,
    }
    items.append(entry)
    _save(items)
    return {"status": "registered", "entry": entry}


@tool(
    name="model_eval",
    description=(
        "对模型跑评估并写入登记簿:传入模型对已标注账号的风险分 {uid: score}"
        "(越大越可疑),计算 AUC/KS/Precision@K/Recall/FPR/FNR/混淆矩阵。"
        "评估数据集指纹必须等于模型训练指纹,否则拒绝(换数据集评出的指标"
        "不能冒充训练集表现)。结果是 shadow->challenger 评估门禁的依据。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "模型名"},
            "version": {"type": "string", "description": "版本号"},
            "scores": {"type": "object",
                       "description": "模型风险分 {uid: score},越大越可疑"},
        },
        "required": ["name", "version", "scores"],
    },
)
def model_eval(name: str, version: str, scores: Dict[str, float]):
    items = _load()
    entry = _find(items, name, version)
    if entry is None:
        return {"error": "模型未登记: %s %s" % (name, version)}
    if not isinstance(scores, dict) or not scores:
        return {"error": "scores 必须是非空 {uid: score}"}
    from .dataset import dataset_fingerprint
    from ..metrics import evaluate  # 惰性:数学本体在 agent/metrics.py
    fp = dataset_fingerprint()
    if fp != entry.get("train_fingerprint"):
        return {"error": "fingerprint 不匹配:评估数据集 %s != 训练指纹 %s"
                         "(评估必须用训练同源数据)" % (fp, entry["train_fingerprint"])}
    labels = load_labels()
    metrics = evaluate(scores, labels)
    metrics["eval_fingerprint"] = fp
    entry["metrics"] = metrics
    entry["evaluated_at"] = _now_iso()
    _save(items)
    return {"status": "evaluated", "name": name, "version": version,
            "metrics": metrics}


@tool(
    name="model_promote",
    description=(
        "模型状态转移:candidate->shadow 自动;shadow->challenger 需已通过"
        "评估门禁(先 model_eval,且指纹匹配);challenger->champion 必须走"
        "审批(提交待审批,人批准后生效,champion 同时只有一个)。不允许重复"
        "晋升。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "模型名"},
            "version": {"type": "string", "description": "版本号"},
            "to": {"type": "string", "enum": ["shadow", "challenger", "champion"],
                   "description": "目标状态"},
            "reason": {"type": "string", "description": "晋升理由(进审批与审计)"},
        },
        "required": ["name", "version", "to"],
    },
)
def model_promote(name: str, version: str, to: str, reason: str = ""):
    items = _load()
    entry = _find(items, name, version)
    if entry is None:
        return {"error": "模型未登记: %s %s" % (name, version)}
    cur = entry["status"]
    if to not in _ALLOWED_FORWARD.get(cur, ()):
        return {"error": "非法转移 %s -> %s(允许: %s)"
                         % (cur, to, _ALLOWED_FORWARD.get(cur, ()) or "无")}
    if to == "shadow":
        entry["status"] = "shadow"
        _save(items)
        return {"status": "promoted", "name": name, "version": version,
                "to": "shadow", "note": "shadow 自动提交(观察期)"}
    if to == "challenger":
        m = entry.get("metrics") or {}
        if not m or m.get("eval_fingerprint") != entry.get("train_fingerprint"):
            return {"error": "评估门禁:先 model_eval 且评估指纹须与训练指纹一致"
                             "(当前 metrics=%s)" % bool(m)}
        entry["status"] = "challenger"
        _save(items)
        return {"status": "promoted", "name": name, "version": version,
                "to": "challenger", "note": "已过评估门禁"}
    # challenger -> champion:必须人审批
    aid = _submit_pending({
        "kind": "model_promote", "name": name, "version": version,
        "to": "champion", "reason": reason, "requested_at": _now_iso(),
    })
    return {"status": "pending_confirmation", "action_id": aid,
            "note": "已提交待审批,人批准后 champion 才生效(旧 champion 自动退役)"}


def apply_champion_promote(action: Dict, decided_by: str) -> Dict:
    """actions.decide 批准后调用:旧 champion 退役,新 champion 上线。"""
    items = _load()
    entry = _find(items, action["name"], action["version"])
    if entry is None:
        raise ValueError("模型未登记: %s %s" % (action["name"], action["version"]))
    if entry["status"] != "challenger":
        raise ValueError("状态机拒绝: %s 当前为 %s,非 challenger"
                         % (entry["name"], entry["status"]))
    for m in items:
        if m["status"] == "champion":
            m["status"] = "deprecated"
            m["retired_at"] = _now_iso()
            m["note"] = (m.get("note", "") + ";被 %s %s 顶替" % (entry["name"], entry["version"])).strip(";")
    entry["status"] = "champion"
    entry["approval_id"] = str(action["action_id"])
    entry["deployed_at"] = _now_iso()
    entry["approved_by"] = decided_by
    _save(items)
    return {"name": entry["name"], "version": entry["version"],
            "status": "champion", "approval_id": entry["approval_id"]}


@tool(
    name="model_rollback",
    description=(
        "提交 champion 回滚申请(走审批,批准后状态置 rollback 并写审计)。"
        "只允许对当前 champion 回滚;非 champion 回滚是非法操作。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "模型名"},
            "version": {"type": "string", "description": "版本号"},
            "reason": {"type": "string", "description": "回滚原因(进审批与审计)"},
        },
        "required": ["name", "version", "reason"],
    },
)
def model_rollback(name: str, version: str, reason: str = ""):
    items = _load()
    entry = _find(items, name, version)
    if entry is None:
        return {"error": "模型未登记: %s %s" % (name, version)}
    if entry["status"] != "champion":
        return {"error": "非法回滚: %s 状态为 %s,只有 champion 可回滚"
                         % (name, entry["status"])}
    aid = _submit_pending({
        "kind": "model_rollback", "name": name, "version": version,
        "reason": reason, "requested_at": _now_iso(),
    })
    return {"status": "pending_confirmation", "action_id": aid,
            "note": "已提交待审批,批准后回滚并写审计"}


def apply_rollback(action: Dict, decided_by: str) -> Dict:
    """actions.decide 批准后调用:状态置 rollback,retired_at 落审计。"""
    items = _load()
    entry = _find(items, action["name"], action["version"])
    if entry is None:
        raise ValueError("模型未登记: %s %s" % (action["name"], action["version"]))
    if entry["status"] != "champion":
        raise ValueError("非法回滚: %s 状态为 %s" % (entry["name"], entry["status"]))
    entry["status"] = "rollback"
    entry["retired_at"] = _now_iso()
    entry["approval_id"] = str(action["action_id"])
    entry["approved_by"] = decided_by
    _save(items)
    return {"name": entry["name"], "version": entry["version"],
            "status": "rollback", "retired_at": entry["retired_at"]}


@tool(
    name="model_status",
    description=(
        "查询模型生命周期状态:candidate/shadow/challenger/champion/deprecated/"
        "rollback,含训练指纹/特征目录版本/评估指标/审批与部署时间。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "模型名(可空=全部)"},
            "version": {"type": "string", "description": "版本号(可空=该名下全部)"},
        },
    },
)
def model_status(name: str = "", version: str = ""):
    items = _load()
    if name:
        items = [m for m in items if m["name"] == name]
    if version:
        items = [m for m in items if m["version"] == version]
    champions = [m["name"] + " " + m["version"] for m in items
                 if m["status"] == "champion"]
    return {"count": len(items), "models": items, "champions": champions}


@tool(
    name="model_list",
    description=("列出已登记模型(等价 model_status 空参查询)。"),
    parameters={"type": "object", "properties": {}},
)
def model_list():
    r = model_status()
    return {"count": r["count"], "models": r["models"]}


@tool(
    name="model_compare",
    description=(
        "Champion vs Challenger 指标对比表(metric/champion/challenger/delta),"
        "基于各自最近一次 model_eval 的结果;样本数不齐会在结果中注明。"
        "评估门禁用,不进生产。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "challenger_name": {"type": "string", "description": "挑战者模型名"},
            "challenger_version": {"type": "string", "description": "挑战者版本"},
            "champion_name": {"type": "string", "description": "当前 champion 名"},
            "champion_version": {"type": "string", "description": "当前 champion 版本"},
        },
        "required": ["challenger_name", "challenger_version",
                     "champion_name", "champion_version"],
    },
)
def model_compare(challenger_name: str, challenger_version: str,
                  champion_name: str, champion_version: str):
    items = _load()
    ch = _find(items, champion_name, champion_version)
    cg = _find(items, challenger_name, challenger_version)
    if ch is None or cg is None:
        return {"error": "champion 或 challenger 未登记"}
    cm, gm = ch.get("metrics") or {}, cg.get("metrics") or {}
    if not cm or not gm:
        return {"error": "双方都须先 model_eval 才能对比"
                         "(champion metrics=%s, challenger metrics=%s)"
                         % (bool(cm), bool(gm))}
    from ..metrics import compare
    result = compare(cm, gm)
    result["champion"] = "%s %s" % (champion_name, champion_version)
    result["challenger"] = "%s %s" % (challenger_name, challenger_version)
    return result
