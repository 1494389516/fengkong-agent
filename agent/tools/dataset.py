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


def _subset_fingerprint(uids: List[str]) -> str:
    """只含子集账号的 events + labels 内容哈希:账号集变了指纹必变,
    训练/评估子集因此天然可区分、不可冒充。"""
    h = hashlib.sha256()
    uids = sorted(uids)
    sub_evs = sorted((e for e in load_events() if e["uid"] in uids),
                     key=lambda e: (e["uid"], e["ts"]))
    labs = load_labels()
    sub_labs = {u: labs[u] for u in uids if u in labs}
    h.update(json.dumps(sub_evs, ensure_ascii=False, sort_keys=True).encode("utf-8"))
    h.update(json.dumps(sub_labs, ensure_ascii=False, sort_keys=True).encode("utf-8"))
    return h.hexdigest()[:16]


def split_datasets(split_ratio: float = 0.7) -> Dict:
    """训练/评估数据集的时间切分(P0-1 防泄漏门禁的事实源)。

    按账号最后事件时间排序,前 split_ratio 为训练集、其余为评估集:
      - 训练/评估账号零重叠(disjoint=True);
      - 评估账号的最后事件全部晚于训练账号 —— time-based split,不是
        同口径抽样。泛化评估 = 用模型没见过的、更晚的行为检验;
      - 两侧指纹为子集内容哈希(build_dataset 导出 + model_eval 校验用)。
    切分确定性:同数据同参数必然同切分。标签不足 2 个时返回 error
    (单侧空集无法做泛化评估,宁缺毋假)。
    """
    labels = load_labels()
    if not labels:
        return {"error": "无标签:先按 data/labeling_sop.md 打标再切分"}
    if len(labels) < 2:
        return {"error": "标签账号不足 2 个,时间切分无法形成训练/评估两侧"}
    events = load_events()
    last_ts: Dict[str, float] = {}
    for e in events:
        last_ts[e["uid"]] = max(last_ts.get(e["uid"], 0), e["ts"])
    ordered = sorted(labels.keys(), key=lambda u: (last_ts.get(u, 0), u))
    n_train = int(len(ordered) * split_ratio)
    n_train = max(1, min(n_train, len(ordered) - 1))  # 两侧至少 1 个账号
    train = ordered[:n_train]
    eval_ = ordered[n_train:]
    return {
        "split_ratio": split_ratio,
        "train_accounts": train,
        "eval_accounts": eval_,
        "train_count": len(train),
        "eval_count": len(eval_),
        "train_fingerprint": _subset_fingerprint(train),
        "eval_fingerprint": _subset_fingerprint(eval_),
        "cutoff_ts": last_ts.get(train[-1]),
        "disjoint": True,
        "note": "时间切分:按账号最后事件 ts 排序,评估账号全部晚于训练账号;"
                "指纹为子集内容哈希,两侧零重叠",
    }


def _shared_device_accounts(uid: str) -> int:
    """反向基数(纯 Python):该账号用过的设备中被最多账号共用的那台的账号数。"""
    dev_uids: Dict[str, set] = {}
    for e in load_events():
        dev_uids.setdefault(e["device_id"], set()).add(e["uid"])
    used = {e["device_id"] for e in load_events() if e["uid"] == uid}
    return max((len(dev_uids[d]) for d in used), default=0)


def _feature_rows(uids: List[str]) -> tuple:
    """对一组账号导出 point-in-time 特征行 + 跳过清单。"""
    events = load_events()
    last_ts: Dict[str, float] = {}
    for e in events:
        last_ts[e["uid"]] = max(last_ts.get(e["uid"], 0), e["ts"])
    labels = load_labels()
    rows: List[Dict] = []
    skipped: List[str] = []
    for uid in uids:
        lab = labels.get(uid)
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
    return rows, skipped


def _export(rows: List[Dict], fp: str, side: str) -> Dict:
    """落盘一侧数据集(CSV + manifest),返回路径与摘要。"""
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    csv_path = OUT_DIR / ("%s_features_%s.csv" % (side, fp))
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["uid", "label"] + list(MODELING_COLUMNS))
        writer.writeheader()
        writer.writerows(rows)
    label_counts: Dict[str, int] = {}
    for r in rows:
        label_counts[r["label"]] = label_counts.get(r["label"], 0) + 1
    manifest = {
        "fingerprint": fp,
        "side": side,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "rows": len(rows),
        "label_counts": label_counts,
        "columns": ["uid", "label"] + list(MODELING_COLUMNS),
        "point_in_time": "as_of = 账号最后事件 ts(只用当时已知行为)",
        "feature_source": "featurelib.account_features(与规则评估同源)",
    }
    manifest_path = OUT_DIR / ("%s_features_%s.manifest.json" % (side, fp))
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=1),
                             encoding="utf-8")
    return {"csv_path": str(csv_path), "manifest_path": str(manifest_path),
            "manifest": manifest}


@tool(
    name="build_dataset",
    description=(
        "把标签与 point-in-time 特征快照导出为建模数据集(CSV + manifest),"
        "特征口径与规则评估同源(featurelib 单点)。只返回路径与摘要,数据本体"
        "落盘不进上下文;manifest 带源数据指纹,复现有据。"
        "split_ratio 给出时按账号最后事件时间切分,导出 train + eval 两份"
        "(评估侧全部晚于训练侧,零重叠) —— 模型评估的防泄漏前提;不给时"
        "导出全量单份(兼容旧调用)。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "split_ratio": {"type": "number",
                            "description": "训练占比 0~1(可空;给 0.7 等值时导出 train+eval 两份)"},
        },
    },
)
def build_dataset(split_ratio: float = None):
    labels = load_labels()
    if not labels:
        return {"error": "无标签:先按 data/labeling_sop.md 打标再导出"}
    if split_ratio is not None:
        sp = split_datasets(split_ratio)
        if "error" in sp:
            return sp
        rows_train, skip_train = _feature_rows(sp["train_accounts"])
        rows_eval, skip_eval = _feature_rows(sp["eval_accounts"])
        train = _export(rows_train, sp["train_fingerprint"], "train")
        eval_ = _export(rows_eval, sp["eval_fingerprint"], "eval")
        return {
            "split": True,
            "split_ratio": split_ratio,
            "train": train,
            "eval": eval_,
            "train_accounts": sp["train_accounts"],
            "eval_accounts": sp["eval_accounts"],
            "cutoff_ts": sp["cutoff_ts"],
            "disjoint": sp["disjoint"],
            "note": sp["note"],
            "leakage_gate": "model_eval 只接受 eval 切分指纹(≠训练指纹)",
        }
    rows, skipped = _feature_rows(sorted(labels.keys()))
    fp = dataset_fingerprint()
    exp = _export(rows, fp, "train")
    exp["manifest"]["skipped_no_events"] = skipped
    return {"split": False, "csv_path": exp["csv_path"],
            "manifest_path": exp["manifest_path"], "manifest": exp["manifest"]}
