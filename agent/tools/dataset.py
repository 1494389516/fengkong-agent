# -*- coding: utf-8 -*-
"""建模样本导出:把标签 + point-in-time 特征快照导出成训练集。

算法人从"策略"跨到"建模"的桥:agent 的取证口径(featurelib 单一事实源)
直接变成建模数据 —— 特征定义与规则评估同源,不会出现"策略用一套数、
模型训另一套数"的口径漂移。

纪律:
  - point-in-time:每个账号的特征取其最后事件的 ts 作为 as_of(只用
    "当时已知"的行为),与线上建模时点语义一致;
  - 数据不出上下文:只回传路径 + manifest 摘要,CSV 本体落盘
    (与图表旁路同一哲学 —— 训练集进 LLM 上下文是纯浪费);
  - manifest 带内容指纹(events + labels 的 sha256):训练集与源数据
    绑定,复现与追责有据。
纯 stdlib(csv),零新依赖。
"""
import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from . import tool
from .datasource import data_dir, load_events, load_labels
from .featurelib import account_features

# 与群体分析/图表的特征列对齐(featurelib.batch_features 同一组口径)
MODELING_COLUMNS = ("event_count", "distinct_ip", "distinct_device",
                    "coupon_claims", "order_amount_max", "min_gap_seconds",
                    "shared_device_accounts")
OUT_DIR = Path(__file__).resolve().parent.parent.parent / "out" / "datasets"


def dataset_fingerprint() -> str:
    """events + labels 的内容哈希:训练集与源数据绑定的指纹。"""
    h = hashlib.sha256()
    d = data_dir()
    for name in ("events_sample.json", "labels.json"):
        p = d / name
        h.update(p.read_bytes() if p.exists() else b"")
    return h.hexdigest()[:16]


def _shared_device_accounts(uid: str) -> int:
    """反向基数(纯 Python):该账号用过的设备中被最多账号共用的那台的账号数。"""
    dev_uids: Dict[str, set] = {}
    for e in load_events():
        dev_uids.setdefault(e["device_id"], set()).add(e["uid"])
    used = {e["device_id"] for e in load_events() if e["uid"] == uid}
    return max((len(dev_uids[d]) for d in used), default=0)


@tool(
    name="build_dataset",
    description=(
        "把标签与 point-in-time 特征快照导出为建模训练集(CSV + manifest),"
        "特征口径与规则评估同源(featurelib 单点)。只返回路径与摘要,数据本体"
        "落盘不进上下文;manifest 带源数据指纹,复现有据。"
    ),
    parameters={"type": "object", "properties": {}},
)
def build_dataset():
    labels = load_labels()
    events = load_events()
    if not labels:
        return {"error": "无标签:先按 data/labeling_sop.md 打标再导出"}
    last_ts: Dict[str, float] = {}
    for e in events:
        last_ts[e["uid"]] = max(last_ts.get(e["uid"], 0), e["ts"])
    rows: List[Dict] = []
    skipped: List[str] = []
    for uid, lab in sorted(labels.items()):
        as_of = last_ts.get(uid)
        if as_of is None:
            skipped.append(uid)
            continue
        f = account_features(uid, as_of_ts=as_of)
        if not f.get("found"):
            skipped.append(uid)
            continue
        row: Dict = {"uid": uid, "label": lab["label"]}
        for col in MODELING_COLUMNS:
            v = (_shared_device_accounts(uid) if col == "shared_device_accounts"
                 else f.get(col))
            row[col] = "" if v is None else v
        rows.append(row)
    fp = dataset_fingerprint()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    csv_path = OUT_DIR / ("train_features_%s.csv" % fp)
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["uid", "label"] + list(MODELING_COLUMNS))
        writer.writeheader()
        writer.writerows(rows)
    label_counts: Dict[str, int] = {}
    for r in rows:
        label_counts[r["label"]] = label_counts.get(r["label"], 0) + 1
    manifest = {
        "fingerprint": fp,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "rows": len(rows),
        "skipped_no_events": skipped,
        "label_counts": label_counts,
        "columns": ["uid", "label"] + list(MODELING_COLUMNS),
        "point_in_time": "as_of = 账号最后事件 ts(只用当时已知行为)",
        "feature_source": "featurelib.account_features(与规则评估同源)",
    }
    manifest_path = OUT_DIR / ("train_features_%s.manifest.json" % fp)
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=1),
                             encoding="utf-8")
    return {"csv_path": str(csv_path), "manifest_path": str(manifest_path),
            "manifest": manifest}
