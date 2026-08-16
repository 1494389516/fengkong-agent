# -*- coding: utf-8 -*-
"""阈值影子产物:完整证据落盘,pending 只存 ID + 内容哈希。

审批认文件不认 pending 里的摘要 —— 改 JSON 数字骗不过哈希。
产物跟 FK_DATA_DIR,评估隔离目录互不污染。
"""
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict

from .datasource import atomic_write_json, data_dir


def artifacts_dir() -> Path:
    return data_dir() / "shadow_artifacts"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _evidence() -> Dict[str, str]:
    from .dataset import dataset_fingerprint
    from .featurelib import FEATURE_CATALOG_VERSION
    from .label_lifecycle import label_fingerprint
    from .readiness import _git_commit
    return {
        "dataset_fingerprint": dataset_fingerprint(),
        "label_fingerprint": label_fingerprint(),
        "feature_catalog_version": FEATURE_CATALOG_VERSION,
        "git_commit": _git_commit() or "unknown",
    }


def _sha256(obj: Any) -> str:
    blob = json.dumps(obj, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def write_threshold_artifact(overrides: Dict, shadow: Dict) -> Dict[str, Any]:
    """把完整 shadow_compare 结果落成不可抵赖产物,返回 pending 绑定字段。"""
    now = _now()
    ev = _evidence()
    body = {
        "kind": "threshold_shadow",
        "overrides": overrides,
        "result": shadow,
        "created_at": _iso(now),
        "expires_at": _iso(now + timedelta(days=7)),
        **ev,
    }
    digest = _sha256(body)
    artifact_id = digest[:16]
    body["sha256"] = digest
    atomic_write_json(artifacts_dir() / ("%s.json" % artifact_id), body)
    return {
        "artifact_id": artifact_id,
        "sha256": digest,
        "changed_accounts": shadow.get("changed_accounts"),
        "delta": shadow.get("delta"),
        "dataset_fingerprint": ev["dataset_fingerprint"],
        "label_fingerprint": ev["label_fingerprint"],
        "feature_catalog_version": ev["feature_catalog_version"],
        "git_commit": ev["git_commit"],
        "shadowed_at": body["created_at"],
        "expires_at": body["expires_at"],
    }


def verify_threshold_artifact(bind: Dict) -> Dict[str, Any]:
    """审批前核验:文件在、哈希对、指纹未漂、未过期。失败抛 ValueError。"""
    artifact_id = bind.get("artifact_id")
    expect = bind.get("sha256")
    if not artifact_id or not expect:
        raise ValueError("影子产物缺失 artifact_id/sha256,请重新提案")
    path = artifacts_dir() / ("%s.json" % artifact_id)
    if not path.exists():
        raise ValueError("影子产物不存在: %s" % artifact_id)
    try:
        body = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise ValueError("影子产物损坏: %s" % e) from e
    stored = body.pop("sha256", None)
    digest = _sha256(body)
    if stored != expect or digest != expect:
        raise ValueError("影子产物哈希不匹配(已被改写),请重新提案")
    exp = body.get("expires_at") or bind.get("expires_at")
    if exp and exp < _iso(_now()):
        raise ValueError("影子证据已过期(%s),请重新提案" % exp)
    live = _evidence()
    for key in ("dataset_fingerprint", "label_fingerprint",
                "feature_catalog_version"):
        if body.get(key) and body[key] != live[key]:
            raise ValueError("影子产物%s已漂(产物=%s, 当前=%s),请重新提案"
                             % (key, body[key], live[key]))
    return body
