# -*- coding: utf-8 -*-
"""异步任务模型:backtest/scan/replay/model_eval/dataset_build 的 Job 化。

设计:同步 API 全部保留,job 是包在它们外面的异步壳 —— 线程池 + 磁盘
job store(out/jobs/*.json)。未来切 Celery/Redis/Kafka 时,只需把
_execute 的调度换成中间件投递,工具接口与 job 文件契约不动。

状态机:queued -> running -> success | failed | cancelled。
每个 job 记录:job_id/type/status/created_at/started_at/finished_at/
request_fingerprint(参数指纹)/progress/result_path/error。

测试钩子:FK_JOB_TEST_GATE=1 时执行线程在开始前等待该 job 自己的 Event
(job_cancel 只释放对应 job) —— 仅 eval 使用,不影响正常路径。
"""
import hashlib
import json
import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from . import tool
from .datasource import atomic_write_json, file_lock

JOBS_DIR = Path(__file__).resolve().parent.parent.parent / "out" / "jobs"
JOB_TYPES = ("backtest", "scan", "replay", "model_eval", "dataset_build")
STATUSES = ("queued", "running", "success", "failed", "cancelled")

MAX_WORKERS = 4
MAX_PENDING = 64
LEASE_SECONDS = 60
MAX_ATTEMPTS = 3
_pool = ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix="fk-job")
_schedule_mu = threading.Lock()
_scheduled = set()
_CHILD = {"backtest": "rule_backtest", "scan": "scan_all",
          "replay": "strategy_replay", "model_eval": "model_eval",
          "dataset_build": "build_dataset"}


def _job_lock(job_id):
    return file_lock(JOBS_DIR / ("job_%06d.lock" % job_id))


def _authorized(job):
    from .capability import get_scope
    scope = get_scope()
    owner = job.get("authorization", {})
    return (scope is not None and scope.expires_at > time.time()
            and all(getattr(scope, k) == owner.get(k)
                    for k in ("principal", "tenant", "dataset")))


def recover_jobs():
    """Claim persisted work with fencing; invoke at worker startup or poll.

    Interrupted mutations are dead-lettered, never blindly retried.
    """
    with _schedule_mu:
        for path in sorted(JOBS_DIR.glob("job_*.json")):
            if ".result." in path.name:
                continue
            job = json.loads(path.read_text(encoding="utf-8"))
            jid = job["job_id"]
            if jid in _scheduled or len(_scheduled) >= MAX_WORKERS:
                continue
            if job.get("status") not in ("queued", "running"):
                continue
            with _job_lock(jid):
                job = _load_job(jid)
                if job.get("status") == "running" and job.get("lease_until", 0) > time.time():
                    continue
                if job.get("status") not in ("queued", "running"):
                    continue
                if (job.get("attempts", 0) >= MAX_ATTEMPTS or
                        (job.get("status") == "running" and job["type"] in ("model_eval", "dataset_build"))):
                    job.update(status="failed", dead_letter=True,
                               error="interrupted mutation or retry budget exhausted", finished_at=_now_iso())
                    _save_job(job)
                    continue
                token = uuid.uuid4().hex
                job.update(status="running", lease_token=token,
                           lease_until=time.time() + LEASE_SECONDS,
                           attempts=job.get("attempts", 0) + 1)
                _save_job(job)
            _scheduled.add(jid)
            _pool.submit(_run_claim, jid, job, token)


def _run_claim(jid, job, token):
    from .capability import RequestScope, request_scope
    from .packs import request_pack
    stop = threading.Event()
    def heartbeat():
        while not stop.wait(LEASE_SECONDS / 3):
            with _job_lock(jid):
                current = _load_job(jid)
                if current.get("lease_token") != token or current.get("status") != "running":
                    return
                current["lease_until"] = time.time() + LEASE_SECONDS
                _save_job(current)
    heart = threading.Thread(target=heartbeat, daemon=True)
    heart.start()
    try:
        scope = RequestScope(**job["authorization"])
        with request_scope(scope, job.get("user_text", "")), request_pack(job.get("pack", "full")):
            _execute(jid, job["type"], job["params"], token)
    except Exception as exc:
        with _job_lock(jid):
            current = _load_job(jid)
            if current.get("lease_token") == token and current.get("status") == "running":
                current.update(status="failed", error=str(exc), finished_at=_now_iso())
                _save_job(current)
    finally:
        stop.set()
        heart.join(timeout=1)
        with _schedule_mu:
            _scheduled.discard(jid)
        recover_jobs()


_gates: Dict[int, threading.Event] = {}
_gates_mu = threading.Lock()


def _gate_for(job_id: int) -> threading.Event:
    with _gates_mu:
        ev = _gates.get(job_id)
        if ev is None:
            ev = threading.Event()
            _gates[job_id] = ev
        return ev


def _next_job_id() -> int:
    """跨进程/重启安全:job id 从既有文件推导。分配时立刻占位文件,
    避免并发扫目录得到同一个 id。"""
    JOBS_DIR.mkdir(parents=True, exist_ok=True)
    lockp = JOBS_DIR / ".id.lock"
    with file_lock(lockp):
        ids = []
        for p in JOBS_DIR.glob("job_*.json"):
            try:
                ids.append(int(p.stem.split("_")[1]))
            except (ValueError, IndexError):
                continue
        n = (max(ids) if ids else 0) + 1
        atomic_write_json(_job_path(n), {"job_id": n, "status": "allocating"})
        return n


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _job_path(job_id: int) -> Path:
    return JOBS_DIR / ("job_%06d.json" % job_id)


def _request_fingerprint(params: Dict) -> str:
    blob = json.dumps(params, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def _load_job(job_id: int) -> Dict:
    p = _job_path(job_id)
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


def _save_job(job: Dict) -> None:
    atomic_write_json(_job_path(job["job_id"]), job)


def _execute(job_id: int, job_type: str, params: Dict, lease_token=None) -> None:
    """Persist the full result and fence stale workers from committing."""
    with _job_lock(job_id):
        job = _load_job(job_id)
        if job.get("status") == "cancelled" or (lease_token and job.get("lease_token") != lease_token):
            return
        job.update(status="running", started_at=_now_iso(), progress=0)
        _save_job(job)
    if os.environ.get("FK_JOB_TEST_GATE") == "1":
        _gate_for(job_id).wait(timeout=30)
    try:
        from . import dispatch
        if _load_job(job_id).get("status") == "cancelled":
            return
        if job_type == "replay":
            from .capability import enforce
            denied = enforce(_CHILD[job_type], True)
            if denied:
                raise PermissionError(denied)
            from ..replay import replay_batch
            from .datasource import load_events
            result = replay_batch(load_events(), **params)
        else:
            result = dispatch(_CHILD[job_type], params, projection=False)
        if isinstance(result, dict) and (result.get("error") or result.get("status") in ("failed", "error")):
            raise RuntimeError(result.get("error") or "tool failed")
        with _job_lock(job_id):
            job = _load_job(job_id)
            if job.get("status") == "cancelled" or (lease_token and job.get("lease_token") != lease_token):
                return
            path = JOBS_DIR / ("job_%06d.result.json" % job_id)
            atomic_write_json(path, result)
            job.update(status="success", progress=1, result_path=str(path),
                       result_status="success", finished_at=_now_iso())
            _save_job(job)
    except Exception as exc:
        with _job_lock(job_id):
            job = _load_job(job_id)
            if job.get("status") != "cancelled" and (not lease_token or job.get("lease_token") == lease_token):
                job.update(status="failed", result_status="error",
                           error="%s: %s" % (type(exc).__name__, exc), finished_at=_now_iso())
                _save_job(job)


@tool(
    name="job_submit",
    description=(
        "提交异步任务(backtest/scan/replay/model_eval/dataset_build),返回 "
        "job_id;用 job_status 轮询、job_result 取产物、job_cancel 取消。"
        "同步 API 仍保留,本工具是重任务的异步形态。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "type": {"type": "string", "enum": list(JOB_TYPES),
                     "description": "任务类型"},
            "params": {"type": "object",
                       "description": "任务参数(与对应同步工具一致)"},
        },
        "required": ["type"],
    },
)
def job_submit(type: str, params: Dict = None):
    if type not in JOB_TYPES:
        return {"error": "未知任务类型: %s(可用 %s)" % (type, JOB_TYPES)}
    from .capability import enforce, get_scope, get_user_text
    from .packs import current, allows
    denied = enforce("job_submit", True) or enforce(_CHILD[type], True)
    if denied or not allows(_CHILD[type]):
        return {"error": denied or "child tool pack denied"}
    scope = get_scope()
    if scope is None:
        return {"error": "missing authorization"}
    params = params or {}
    JOBS_DIR.mkdir(parents=True, exist_ok=True)
    with file_lock(JOBS_DIR / ".budget.lock"):
        pending = sum(1 for p in JOBS_DIR.glob("job_*.json")
                      if ".result." not in p.name and
                      json.loads(p.read_text()).get("status") in ("allocating", "queued", "running"))
        if pending >= MAX_PENDING:
            return {"error": "job backlog budget exhausted"}
        job_id = _next_job_id()
    job = {
        "job_id": job_id,
        "type": type,
        "authorization": scope.snapshot(),
        "user_text": get_user_text(),
        "pack": current(),
        "params": params,
        "status": "queued",
        "created_at": _now_iso(),
        "started_at": None,
        "finished_at": None,
        "request_fingerprint": _request_fingerprint(params),
        "progress": 0,
        "result_path": None,
        "error": None,
    }
    _save_job(job)
    recover_jobs()
    return {"status": "queued", "job_id": job_id, "type": type}


@tool(
    name="job_status",
    description=(
        "查询任务状态:queued/running/success/failed/cancelled,含起止时间/"
        "参数指纹/进度/产物路径/错误。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "job_id": {"type": "integer", "description": "任务 id"},
        },
        "required": ["job_id"],
    },
)
def job_status(job_id: int):
    job = _load_job(job_id)
    if not job or not _authorized(job):
        return {"error": "任务不存在或无权限: #%d" % job_id}
    recover_jobs()
    job = _load_job(job_id)
    return {k: v for k, v in job.items() if k not in ("authorization", "user_text")}


@tool(
    name="job_result",
    description=(
        "取任务产物:success 返回结果对象;未完成/失败返回状态与错误。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "job_id": {"type": "integer", "description": "任务 id"},
        },
        "required": ["job_id"],
    },
)
def job_result(job_id: int):
    job = _load_job(job_id)
    if not job or not _authorized(job):
        return {"error": "任务不存在或无权限: #%d" % job_id}
    if job["status"] != "success":
        return {"status": job["status"], "error": job.get("error"),
                "note": "任务未成功,无产物"}
    rp = Path(job["result_path"])
    result = json.loads(rp.read_text(encoding="utf-8")) if rp.exists() else None
    return {"status": "success", "job_id": job_id, "result": result}


@tool(
    name="job_cancel",
    description=(
        "取消任务:queued/running 均可提交取消;已取消的 job 不产出结果。"
        "执行中的任务在启动前检查取消标记(不强行中断计算,防脏产物)。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "job_id": {"type": "integer", "description": "任务 id"},
        },
        "required": ["job_id"],
    },
)
def job_cancel(job_id: int):
    with _job_lock(job_id):
        return _cancel_locked(job_id)


def _cancel_locked(job_id):
    job = _load_job(job_id)
    if not job or not _authorized(job):
        return {"error": "任务不存在或无权限: #%d" % job_id}
    if job["status"] in ("success", "failed"):
        return {"error": "任务已终态(%s),不可取消" % job["status"]}
    if job["status"] == "cancelled":
        return {"status": "cancelled", "job_id": job_id}
    job["status"] = "cancelled"
    _save_job(job)
    _gate_for(job_id).set()
    return {"status": "cancelled", "job_id": job_id}
