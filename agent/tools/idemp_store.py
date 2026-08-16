# -*- coding: utf-8 -*-
"""决策幂等存储:事件指纹唯一键,跨进程可见,计算中占位合并。

骨架等价于「带唯一约束的幂等表」:同一 data_dir 上的多个 serve 进程
看到同一份 decide_idemp.json。进程内 in-flight 由调用方 Event 处理;
跨进程靠 status=computing 占位 + 轮询。
"""
import os
import time
from typing import Any, Dict, Optional

from .datasource import _load_json, atomic_write_json, data_dir, file_lock

_STALE_S = 30.0


def idemp_path():
    return data_dir() / "decide_idemp.json"


def _load() -> Dict[str, Any]:
    p = idemp_path()
    try:
        obj = _load_json(p)
    except FileNotFoundError:
        return {}
    except ValueError:
        return {}
    return obj if isinstance(obj, dict) else {}


def lookup(fp: str) -> Optional[Dict]:
    rec = _load().get(fp)
    if rec and rec.get("status") == "done":
        return rec.get("public")
    return None


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


def complete(fp: str, public: Dict) -> None:
    p = idemp_path()
    with file_lock(p):
        store = _load()
        store[fp] = {"status": "done", "public": public}
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
