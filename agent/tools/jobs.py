# -*- coding: utf-8 -*-
"""异步任务模型:backtest/scan/replay/model_eval/dataset_build 的 Job 化。

设计:同步 API 全部保留,job 是包在它们外面的异步壳 —— 线程池 + 磁盘
job store(out/jobs/*.json)。未来切 Celery/Redis/Kafka 时,只需把
_execute 的调度换成中间件投递,工具接口与 job 文件契约不动。

状态机:queued -> running -> success | failed | cancelled。
每个 job 记录:job_id/type/status/created_at/started_at/finished_at/
request_fingerprint(参数指纹)/progress/result_path/error。

测试钩子:FK_JOB_TEST_GATE=1 时执行线程在开始前等待一个模块级 Event
(job_cancel 会释放它) —— 仅 eval 使用,不影响正常路径。
"""
import hashlib
import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from . import tool

JOBS_DIR = Path(__file__).resolve().parent.parent.parent / "out" / "jobs"
JOB_TYPES = ("backtest", "scan", "replay", "model_eval", "dataset_build")
STATUSES = ("queued", "running", "success", "failed", "cancelled")

_gate = threading.Event()  # 测试钩子:执行前等待
_next_id = 0
_next_id_lock = threading.Lock()


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
    JOBS_DIR.mkdir(parents=True, exist_ok=True)
    _job_path(job["job_id"]).write_text(
        json.dumps(job, ensure_ascii=False, indent=1), encoding="utf-8")


def _execute(job_id: int, job_type: str, params: Dict) -> None:
    """在线程里执行任务,更新状态与产物路径。"""
    job = _load_job(job_id)
    job["status"] = "running"
    job["started_at"] = _now_iso()
    job["progress"] = 0
    _save_job(job)
    if os.environ.get("FK_JOB_TEST_GATE") == "1":
        _gate.wait(timeout=30)
    job = _load_job(job_id)
    if job.get("status") == "cancelled":  # cancel 在启动前标记
        job["finished_at"] = _now_iso()
        _save_job(job)
        return
    try:
        if job_type == "backtest":
            result = __import__("agent.tools", fromlist=["dispatch"]).dispatch(
                "rule_backtest", params)
        elif job_type == "scan":
            result = __import__("agent.tools", fromlist=["dispatch"]).dispatch(
                "scan_all", params)
        elif job_type == "replay":
            from ..replay import replay_batch
            from .datasource import load_events
            events = load_events()
            result = replay_batch(events, **params)
            result = {"records": len(result),
                      "first": result[0] if result else None}
        elif job_type == "model_eval":
            result = __import__("agent.tools", fromlist=["dispatch"]).dispatch(
                "model_eval", params)
        elif job_type == "dataset_build":
            result = __import__("agent.tools", fromlist=["dispatch"]).dispatch(
                "build_dataset", params)
        else:
            raise ValueError("未知任务类型: %s" % job_type)
        job = _load_job(job_id)
        job["status"] = "success"
        job["progress"] = 1
        job["result_path"] = str(JOBS_DIR / ("job_%06d.result.json" % job_id))
        (JOBS_DIR / ("job_%06d.result.json" % job_id)).write_text(
            json.dumps(result, ensure_ascii=False, indent=1, default=str),
            encoding="utf-8")
    except Exception as e:  # noqa: BLE001 任务失败落 error,不中断其他 job
        job = _load_job(job_id)
        job["status"] = "failed"
        job["error"] = "%s: %s" % (type(e).__name__, e)
    finally:
        job["finished_at"] = _now_iso()
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
    global _next_id
    if type not in JOB_TYPES:
        return {"error": "未知任务类型: %s(可用 %s)" % (type, JOB_TYPES)}
    params = params or {}
    with _next_id_lock:
        _next_id += 1
        job_id = _next_id
    job = {
        "job_id": job_id,
        "type": type,
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
    t = threading.Thread(target=_execute, args=(job_id, type, params),
                         daemon=True)
    t.start()
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
    if not job:
        return {"error": "任务不存在: #%d" % job_id}
    return job


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
    if not job:
        return {"error": "任务不存在: #%d" % job_id}
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
    job = _load_job(job_id)
    if not job:
        return {"error": "任务不存在: #%d" % job_id}
    if job["status"] in ("success", "failed"):
        return {"error": "任务已终态(%s),不可取消" % job["status"]}
    if job["status"] == "cancelled":
        return {"status": "cancelled", "job_id": job_id}
    job["status"] = "cancelled"
    _save_job(job)
    _gate.set()  # 释放测试钩子,让执行线程尽快走到取消检查
    return {"status": "cancelled", "job_id": job_id}
