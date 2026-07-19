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


def load_accounts() -> Dict[str, Dict]:
    """账号主档(注册上下文 + 价值信息)。文件缺失返回空:临时数据集/
    旧数据集没有主档时,依赖它的规则(R004)与档案字段自动降级。"""
    try:
        return {k: v for k, v in _load_json(data_dir() / "accounts.json").items()
                if not k.startswith("_")}
    except FileNotFoundError:
        return {}


def load_decisions():
    """生产决策日志(骨架里为模拟文件,设定由生产引擎写入)。
    缺失返回 None —— 表示"对账不可用",与空日志([]) 语义不同。"""
    try:
        obj = _load_json(data_dir() / "decisions_log.json")
    except FileNotFoundError:
        return None
    return obj.get("decisions") if isinstance(obj, dict) else obj


def load_ip_intel() -> Dict[str, Dict]:
    """IP 情报库(按 /24 网段)。文件缺失返回空:未知段按 unknown 处理。"""
    try:
        return {k: v for k, v in _load_json(data_dir() / "ip_intel.json").items()
                if not k.startswith("_")}
    except FileNotFoundError:
        return {}


def load_reports() -> list:
    """举报记录。文件缺失返回空列表。"""
    try:
        return _load_json(data_dir() / "reports.json")
    except FileNotFoundError:
        return []


def blacklist_path() -> Path:
    return data_dir() / "blacklist.json"


def thresholds_path() -> Path:
    return data_dir() / "thresholds.json"


def pending_actions_path() -> Path:
    return data_dir() / "pending_actions.json"


def audit_log_path() -> Path:
    return data_dir() / "audit.jsonl"
