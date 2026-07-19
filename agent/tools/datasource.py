# -*- coding: utf-8 -*-
"""数据源单点:所有工具经此读写数据,换数据集/接真实数仓只改这里。

数据集切换(每次调用时解析,便于 eval 临时切换):
  FK_DATA_DIR=/abs/path  最高优先级,直接指定数据目录(eval 用临时目录测写流程)
  FK_DATASET=gen         读 data/gen/(gen_sample.py 生成的大样本)
  默认                   读 data/(手工小样本,eval 的确定性基线)

读缓存按 (路径, mtime_ns) 失效 —— 大样本下 rule_eval 每事件都要读全量事件,
不缓存就是 O(N^2) 次 JSON 解析。
"""
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Tuple

ROOT = Path(__file__).resolve().parent.parent.parent

_cache: Dict[Path, Tuple[int, Any]] = {}


def data_dir() -> Path:
    override = os.environ.get("FK_DATA_DIR")
    if override:
        return Path(override)
    if os.environ.get("FK_DATASET") == "gen":
        return ROOT / "data" / "gen"
    return ROOT / "data"


def _load_json(path: Path):
    mtime = path.stat().st_mtime_ns
    hit = _cache.get(path)
    if hit and hit[0] == mtime:
        return hit[1]
    obj = json.loads(path.read_text(encoding="utf-8"))
    _cache[path] = (mtime, obj)
    return obj


def load_events() -> List[Dict]:
    return _load_json(data_dir() / "events_sample.json")


def load_blacklist() -> List[Dict]:
    return _load_json(data_dir() / "blacklist.json")


def load_labels() -> Dict[str, Dict]:
    return {k: v for k, v in _load_json(data_dir() / "labels.json").items()
            if not k.startswith("_")}


def blacklist_path() -> Path:
    return data_dir() / "blacklist.json"


def thresholds_path() -> Path:
    return data_dir() / "thresholds.json"


def pending_actions_path() -> Path:
    return data_dir() / "pending_actions.json"


def audit_log_path() -> Path:
    return data_dir() / "audit.jsonl"
