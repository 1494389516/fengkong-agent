# -*- coding: utf-8 -*-
"""标签生命周期:标签数据可版本化、变化可追踪、修正有血缘。

- label_version:把当前 labels.json 快照进 data/label_snapshots.json
  (内容指纹 + 逐 uid 标签),同指纹不重复打;
- label_diff:两个快照或当前 vs 最近快照的差异(新增/删除/变更 uid,含
  旧/新标签);
- label_refresh:语义同 label_version,用于"申诉修正后的再快照"(记录
  note);
- label_fingerprint:labels.json 内容哈希 —— 回测结果携带它,评估口径与
  标签版本绑定;
- 血缘:申诉导致的标签修正由 feedback.apply_appeal_decision 调用
  write_label_lineage 落一行(uid/工单/旧标签→新标签/审批人)—— 不
  允许静默修改历史标签,每一次修正都有来源可查。

评估血缘链:event fingerprint + label fingerprint + feature fingerprint
= evaluation lineage。
"""
import hashlib
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional

from . import tool
from .datasource import data_dir, labels_path

LABEL_SNAPSHOTS_FILE = "label_snapshots.json"
LABEL_LINEAGE_FILE = "label_lineage.jsonl"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _snapshots_path():
    return data_dir() / LABEL_SNAPSHOTS_FILE


def _lineage_path():
    return data_dir() / LABEL_LINEAGE_FILE


def label_fingerprint() -> str:
    """labels.json 内容哈希(评估口径与标签版本绑定的指纹)。"""
    p = labels_path()
    blob = p.read_bytes() if p.exists() else b""
    return hashlib.sha256(blob).hexdigest()[:16]


def _entries() -> Dict[str, str]:
    """{uid: label},跳过 _comment 与非法记录。"""
    p = labels_path()
    if not p.exists():
        return {}
    raw = json.loads(p.read_text(encoding="utf-8"))
    out = {}
    for k, v in raw.items():
        if k.startswith("_"):
            continue
        lab = v.get("label") if isinstance(v, dict) else v
        if lab in ("fraud", "normal"):
            out[k] = lab
    return out


def _load_snapshots() -> List[Dict]:
    p = _snapshots_path()
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else []


def _save_snapshots(items: List[Dict]) -> None:
    _snapshots_path().write_text(json.dumps(items, ensure_ascii=False, indent=1),
                                 encoding="utf-8")


def _snapshot_record(note: str) -> Dict:
    return {"fingerprint": label_fingerprint(),
            "taken_at": _now_iso(),
            "note": note,
            "labels": _entries()}


@tool(
    name="label_version",
    description=(
        "给当前标签数据打版本快照(内容指纹 + 逐 uid 标签)。同指纹不重复打。"
        "每次回测记录 label_fingerprint,标签变化可追踪,评估口径与标签版本"
        "绑定。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "note": {"type": "string", "description": "快照说明(可空)"},
        },
    },
)
def label_version(note: str = ""):
    snap = _snapshot_record(note or "manual")
    items = _load_snapshots()
    if items and items[-1]["fingerprint"] == snap["fingerprint"]:
        return {"status": "already_snapshotted",
                "fingerprint": snap["fingerprint"],
                "note": "标签未变化,不重复打快照"}
    items.append(snap)
    _save_snapshots(items)
    return {"status": "snapshotted", "fingerprint": snap["fingerprint"],
            "label_count": len(snap["labels"])}


@tool(
    name="label_diff",
    description=(
        "标签差异:对比两个快照(version_a 为快照指纹;version_b 缺省=当前"
        "标签数据),输出新增/删除/变更的 uid 与旧新标签 —— 变化可追踪,"
        "不允许静默修改历史标签。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "version_a": {"type": "string", "description": "旧快照指纹"},
            "version_b": {"type": "string",
                          "description": "新快照指纹(可空=当前标签数据)"},
        },
        "required": ["version_a"],
    },
)
def label_diff(version_a: str, version_b: str = ""):
    items = _load_snapshots()
    a = next((s for s in items if s["fingerprint"] == version_a), None)
    if a is None:
        return {"error": "快照不存在: %s(可用: %s)" % (
            version_a, [s["fingerprint"] for s in items] or "无,先 label_version")}
    labels_b = _entries() if not version_b else next(
        (s["labels"] for s in items if s["fingerprint"] == version_b), None)
    if labels_b is None:
        return {"error": "快照不存在: %s" % version_b}
    added = sorted(k for k in labels_b if k not in a["labels"])
    removed = sorted(k for k in a["labels"] if k not in labels_b)
    changed = [{"uid": k, "old": a["labels"][k], "new": labels_b[k]}
               for k in a["labels"] if k in labels_b and a["labels"][k] != labels_b[k]]
    return {"version_a": version_a, "version_b": version_b or "(当前)",
            "added": added, "removed": removed, "changed": changed,
            "changed_count": len(changed)}


@tool(
    name="label_refresh",
    description=(
        "申诉/人工修正后的再快照(语义同 label_version,note 记录修正来源)。"
        "标签修正必须经申诉核实等正规渠道,修正后刷新快照使血缘连续。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "note": {"type": "string", "description": "修正来源说明"},
        },
        "required": ["note"],
    },
)
def label_refresh(note: str):
    return label_version(note)


def write_label_lineage(uid: str, old_label: Optional[str], new_label: str,
                        source: str, appeal_id: Optional[int] = None,
                        decided_by: str = "cli") -> None:
    """标签修正血缘:feedback.apply_appeal_decision 在修正标签时调用。
    尽力而为:血缘写失败不掀翻审批流程。"""
    try:
        p = _lineage_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "ts": _now_iso(),
                "uid": uid,
                "old_label": old_label,
                "new_label": new_label,
                "source": source,
                "appeal_id": appeal_id,
                "decided_by": decided_by,
            }, ensure_ascii=False) + "\n")
    except Exception:  # noqa: BLE001
        pass
