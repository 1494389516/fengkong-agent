# -*- coding: utf-8 -*-
"""决策幂等存储:业务 event_id 唯一键,跨进程可见,同键计算合并。

骨架等价于「带唯一约束的幂等表」:同一 data_dir 上的多个 serve 进程
看到同一份 decide_idemp.json。serve 使用锁分片 claim() 在整个计算周期
持有 flock，进程崩溃由内核释放；旧 begin/wait API 仅保留脚本兼容。
"""
import fcntl
import hashlib
import os
import threading
import time
from contextlib import contextmanager
from typing import Any, Dict, Optional

from .datasource import _load_json, atomic_write_json, data_dir, file_lock

_STALE_S = 30.0
_DEFAULT_TTL_S = 7 * 24 * 3600
_DEFAULT_MAX_RECORDS = 10000
_CLAIM_STRIPES = 64
_claim_locks = [threading.RLock() for _ in range(_CLAIM_STRIPES)]


class IdempotencyConflict(ValueError):
    """同一业务 event_id 被复用于不同请求体。"""


def idemp_path():
    return data_dir() / "decide_idemp.json"


def _load() -> Dict[str, Any]:
    p = idemp_path()
    try:
        obj = _load_json(p)
    except FileNotFoundError:
        return {}
    if not isinstance(obj, dict):
        raise ValueError("invalid idempotency store schema")
    return obj


def lookup(fp: str, input_fingerprint: str = "") -> Optional[Dict]:
    rec = _load().get(fp)
    if rec and rec.get("status") == "done":
        stored_fp = rec.get("input_fingerprint") or ""
        if input_fingerprint and stored_fp and stored_fp != input_fingerprint:
            raise IdempotencyConflict("event_id 已用于不同请求体")
        completed_at = float(rec.get("completed_at") or 0)
        if completed_at and time.time() - completed_at > ttl_seconds():
            return None
        return rec.get("public")
    return None


def event_key(event_id: str) -> str:
    """业务事件 ID 的稳定存储键；不把原始 ID 暴露在状态文件键名。"""
    return hashlib.sha256(("event_id:" + event_id).encode("utf-8")).hexdigest()[:32]


@contextmanager
def claim(fp: str):
    """同一幂等键跨线程/进程只允许一个计算者。

    使用固定数量的锁分片，既避免每个事件永久留下一个锁文件，又允许不同
    分片并行；进程异常退出时 flock 由内核自动释放，无超时后重复计算窗口。
    """
    stripe = int(hashlib.sha256(fp.encode("utf-8")).hexdigest(), 16) % _CLAIM_STRIPES
    lock = _claim_locks[stripe]
    path = data_dir() / "idemp_claims" / ("claim-%02d.lock" % stripe)
    path.parent.mkdir(parents=True, exist_ok=True)
    with lock:
        with open(path, "a+", encoding="utf-8") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


def begin(fp: str) -> str:
    """hit=已有结论; wait=他人正在算; compute=本进程认领。"""
    p = idemp_path()
    with file_lock(p):
        store = _load()
        rec = store.get(fp) or {}
        if rec.get("status") == "done" and rec.get("public") is not None:
            return "hit"
        if rec.get("status") == "computing":
            pid = rec.get("pid")
            started = float(rec.get("ts") or 0)
            if time.time() - started < _STALE_S and _pid_alive(pid):
                return "wait"
        store[fp] = {"status": "computing", "pid": os.getpid(),
                     "ts": time.time()}
        atomic_write_json(p, store)
        return "compute"


def wait_done(fp: str, timeout: float = 15.0) -> Optional[Dict]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        pub = lookup(fp)
        if pub is not None:
            return pub
        time.sleep(0.05)
    return None


def complete(fp: str, public: Dict, input_fingerprint: str = "") -> None:
    p = idemp_path()
    with file_lock(p):
        store = _load()
        store[fp] = {"status": "done", "public": public,
                     "input_fingerprint": input_fingerprint,
                     "completed_at": time.time()}
        _prune(store)
        atomic_write_json(p, store)


def abort(fp: str) -> None:
    p = idemp_path()
    with file_lock(p):
        store = _load()
        rec = store.get(fp)
        if rec and rec.get("status") == "computing" and rec.get("pid") == os.getpid():
            store.pop(fp, None)
            atomic_write_json(p, store)


def _pid_alive(pid) -> bool:
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _positive_env_int(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)) or default)
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def ttl_seconds() -> int:
    return _positive_env_int("FK_IDEMP_TTL_SECONDS", _DEFAULT_TTL_S)


def _max_records() -> int:
    return _positive_env_int("FK_IDEMP_MAX_RECORDS", _DEFAULT_MAX_RECORDS)


def _prune(store: Dict[str, Any]) -> None:
    now = time.time()
    expired = [k for k, rec in store.items()
               if rec.get("status") == "done"
               and float(rec.get("completed_at") or now) < now - ttl_seconds()]
    for key in expired:
        store.pop(key, None)
    limit = _max_records()
    if len(store) <= limit:
        return
    raise RuntimeError("idempotency capacity exhausted; live records cannot be evicted")
