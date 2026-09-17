# -*- coding: utf-8 -*-
"""数据源单点:所有工具经此读写数据,换数据集/接真实数仓只改这里。

数据集切换(每次调用时解析,便于 eval 临时切换):
  FK_DATA_DIR=/abs/path  最高优先级,直接指定数据目录(eval 用临时目录测写流程)
  FK_DATASET=gen         读 data/gen/(gen_sample.py 生成的大样本)
  默认                   读 data/(手工小样本,eval 的确定性基线)

读缓存按 (路径, mtime_ns) 失效 —— 大样本下 rule_eval 每事件都要读全量事件,
不缓存就是 O(N^2) 次 JSON 解析。

落盘纪律(骨架期):JSON 状态文件必须 os.replace 原子写,跨线程/进程用 flock。
崩溃或磁盘满时旧文件仍是合法 JSON,不能半截覆盖。
"""
from contextvars import ContextVar
import fcntl
import json
import os
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple

ROOT = Path(__file__).resolve().parent.parent.parent

_event_snapshot = ContextVar("online_event_snapshot", default=None)


@contextmanager
def event_snapshot(events, identity):
    token = _event_snapshot.set((identity, events))
    try:
        yield
    finally:
        _event_snapshot.reset(token)


def event_snapshot_identity():
    snapshot = _event_snapshot.get()
    if snapshot is not None:
        return snapshot[0]
    path = data_dir() / "online.sqlite3"
    if not path.exists():
        return None
    # SQLite WAL commits need not alter the main database file. Include both
    # inode and WAL metadata, and tenant/app identity, in feature cache keys.
    from agent.tenancy import current_context
    ctx = current_context()
    versions = []
    for file in (path, Path(str(path) + "-wal")):
        try:
            st = file.stat()
            versions.append((str(file), st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns))
        except FileNotFoundError:
            versions.append((str(file), None))
    return ("online_sql", ctx.tenant if ctx else None, ctx.app if ctx else None, tuple(versions))


_cache: Dict[Path, Tuple[int, Any]] = {}
_cache_lock = threading.RLock()
_io_lock = threading.RLock()


def data_dir() -> Path:
    import sys
    from agent.tenancy import current_context, authorized_dataset
    context = current_context()
    capability = sys.modules.get("agent.tools.capability")
    scope = capability.get_scope() if capability and hasattr(capability, "get_scope") else None
    if context is not None:
        if context.expires_at <= __import__("time").time():
            raise PermissionError("request credential expired")
        if scope is not None and (scope.tenant != context.tenant or scope.dataset != context.dataset):
            raise PermissionError("tool scope and authenticated request differ")
        return Path(context.dataset)
    if scope is not None and os.environ.get("FK_AUTH_CONFIG"):
        if not authorized_dataset(scope.tenant, scope.dataset):
            raise PermissionError("request scope is outside registered dataset")
        return Path(scope.dataset).resolve()
    override = os.environ.get("FK_DATA_DIR")
    path = Path(override) if override else ROOT / "data" / "gen" if os.environ.get("FK_DATASET") == "gen" else ROOT / "data"
    path = path.resolve()
    if scope is not None:
        if (scope.dataset != str(path) or not os.environ.get("FK_SCOPE_TENANT")
                or scope.tenant != os.environ["FK_SCOPE_TENANT"]):
            raise PermissionError("request scope does not match deployment dataset/tenant")
    return path


def output_dir():
    from agent.tenancy import current_context
    import sys
    capability = sys.modules.get("agent.tools.capability")
    scope = capability.get_scope() if capability and hasattr(capability, "get_scope") else None
    return data_dir() / "out" if (current_context() or scope or os.environ.get("FK_AUTH_CONFIG")) else ROOT / "out"


def _load_json(path: Path):
    with _cache_lock:
        try:
            mtime = path.stat().st_mtime_ns
        except FileNotFoundError:
            raise
        hit = _cache.get(path)
        if hit and hit[0] == mtime:
            return hit[1]
        try:
            obj = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise ValueError("JSON 损坏: %s (%s)" % (path, e)) from e
        _cache[path] = (mtime, obj)
        return obj


def invalidate_cache(path: Path = None) -> None:
    with _cache_lock:
        if path is None:
            _cache.clear()
        else:
            _cache.pop(path, None)


def atomic_write_json(path: Path, obj: Any, *, mkdir: bool = True) -> None:
    """写临时文件 + fsync + os.replace。失败时原文件不变。
    mkdir=False 时父目录必须已存在(审批名单落盘失败要能原样抛 OSError,
    申请留在队列)。"""
    path = Path(path)
    if mkdir:
        path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp",
                               dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=1, default=str)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        tmp = None
        invalidate_cache(path)
    finally:
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def atomic_write_text(path: Path, text: str, *, mkdir: bool = True) -> None:
    """原子写 UTF-8 文本；事务恢复 JSONL/原始快照时使用。"""
    path = Path(path)
    if mkdir:
        path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp",
                               dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        tmp = None
        invalidate_cache(path)
    finally:
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass


@contextmanager
def file_lock(path: Path, *, mkdir: bool = True) -> Iterator[None]:
    """同进程 RLock + 跨进程 flock。锁文件是 path + '.lock'。
    mkdir=False 时父目录必须已存在(名单审批失败要能原样抛 OSError)。"""
    path = Path(path)
    if mkdir:
        path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.parent / (path.name + ".lock")
    with _io_lock:
        lf = open(lock_path, "a+", encoding="utf-8")
        try:
            fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(lf.fileno(), fcntl.LOCK_UN)
            finally:
                lf.close()


@contextmanager
def state_write_lock() -> Iterator[None]:
    """序列化 Agent 写工具与人工审批的跨文件读改写事务。

    单文件仍使用各自的 file_lock；本锁负责避免两个写工作流同时读取旧快照
    后互相覆盖，也为审批恢复日志提供稳定的一致性边界。
    """
    with file_lock(data_dir() / ".state_write"):
        yield


def append_jsonl(path: Path, rec: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(rec, ensure_ascii=False) + "\n"
    with file_lock(path):
        with open(path, "a", encoding="utf-8") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())


def load_events(*, limit=None, as_of_ts=None, window_seconds=None) -> List[Dict]:
    if limit is not None and (type(limit) is not int or not 0 <= limit <= 1000000):
        raise ValueError("invalid event limit")
    snapshot = _event_snapshot.get()
    if snapshot is not None:
        rows = snapshot[1]
    elif (data_dir()/"online.sqlite3").exists():
        import sqlite3
        from agent.tenancy import current_context
        db=sqlite3.connect("file:"+str(data_dir()/"online.sqlite3")+"?mode=ro",uri=True)
        try:
            where=[];params=[]
            ctx=current_context()
            if ctx:
                where.extend(["tenant=?","app=?"]);params.extend([ctx.tenant,ctx.app])
            if as_of_ts is not None:
                where.extend(["occurred_at<?","recorded_at<=?"]);params.extend([as_of_ts,as_of_ts])
                if window_seconds is not None:
                    where.append("occurred_at>=?");params.append(as_of_ts-window_seconds)
            query="SELECT body FROM events"+(" WHERE "+" AND ".join(where) if where else "")+" ORDER BY occurred_at,event_id"
            if limit is not None:
                query+=" LIMIT ?";params.append(limit)
            return [json.loads(r[0]) for r in db.execute(query,params)]
        finally:
            db.close()
    else:
        rows = _load_json(data_dir() / "events_sample.json")
    result=[]
    for e in rows:
        ts=e.get("ts",0)
        if as_of_ts is not None and (ts>=as_of_ts or e.get("recorded_at",e.get("received_at",ts))>as_of_ts):
            continue
        if window_seconds is not None and as_of_ts is not None and ts<as_of_ts-window_seconds:
            continue
        if limit is not None and len(result)>=limit:
            break
        result.append(dict(e))
    return result


def load_blacklist() -> List[Dict]:
    from agent.runtime_bundle import current_bundle
    bundle = current_bundle()
    if bundle is not None:
        component = bundle.get("list")
        records = component.get("records") if isinstance(component, dict) else None
        if not isinstance(records, list) or not all(isinstance(row, dict) for row in records):
            raise ValueError("runtime list snapshot must contain records")
        return records
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


def load_device_intel() -> Dict[str, Dict]:
    """设备指纹库(模拟器/root/hook)。文件缺失返回空:未知设备按 unknown 处理。"""
    try:
        return {k: v for k, v in _load_json(data_dir() / "device_intel.json").items()
                if not k.startswith("_")}
    except FileNotFoundError:
        return {}


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


def load_appeals() -> list:
    """误伤申诉记录(被处置用户喊冤的方向,与 reports 的举报方向相反)。
    文件缺失返回空列表。"""
    try:
        return _load_json(data_dir() / "appeals.json")
    except FileNotFoundError:
        return []


def appeals_path() -> Path:
    return data_dir() / "appeals.json"


def watchlist_path() -> Path:
    return data_dir() / "watchlist.json"


def alert_acks_path() -> Path:
    return data_dir() / "alert_acks.json"


def postmortems_path() -> Path:
    return data_dir() / "postmortems.jsonl"


def labels_path() -> Path:
    return data_dir() / "labels.json"


def blacklist_path() -> Path:
    return data_dir() / "blacklist.json"


def thresholds_path() -> Path:
    return data_dir() / "thresholds.json"


def pending_actions_path() -> Path:
    return data_dir() / "pending_actions.json"


def audit_log_path() -> Path:
    return data_dir() / "audit.jsonl"
