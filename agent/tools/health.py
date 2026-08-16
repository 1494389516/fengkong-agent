# -*- coding: utf-8 -*-
"""数据体检工具:在换数据集/接真实数据前检查各数据文件的口径健康度。

背景:骨架用合成数据,字段规整、时间有序;真实导出的第一批数据几乎必然
带脏(缺字段/乱序/枚举漂移/重复),而这类问题会让规则静默失真(例:主档
缺失导致 R004/R005 整条不生效,还看不出来)。体检把这些问题显式化:
- error   = 会让规则/工具出错或静默失真的硬伤(缺必填字段、解析失败、
            重复事件、非法枚举、版本表乱序)
- warning = 值得人工确认的软伤(时间乱序、主档覆盖率<100%、分超界)
- note    = 纯信息(标签覆盖率等,回测口径解释用)

原则:体检只读不写、只报不改;真数据接入的第一道工序,agent 应把它当作
换数据源后的必跑步骤(见 system.md 工具使用提示)。
"""
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

from . import tool
from .datasource import data_dir

EVENT_TYPES = {"login", "order", "coupon_claim"}
LIST_COLORS = {"black", "gray", "white"}
DIMENSIONS = {"uid", "ip", "device_id"}
ACTIONS = {"pass", "review", "reject"}
IP_TYPES = {"residential", "mobile", "idc", "proxy", "unknown"}
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

REQUIRED_JSON_FILES = ("events_sample.json", "blacklist.json")
OPTIONAL_JSON_FILES = ("accounts.json", "labels.json", "thresholds.json",
                       "device_intel.json", "ip_intel.json", "reports.json",
                       "appeals.json", "decisions_log.json", "pending_actions.json")
JSONL_FILES = ("audit.jsonl", "postmortems.jsonl")

SEV_RANK = {"note": 0, "warning": 1, "error": 2}


class _File:
    """单文件体检的累加器:issues 按 kind 聚合,保留少量样本便于人工定位。"""

    def __init__(self) -> None:
        self.exists = False
        self.parse_ok = False
        self.records = 0
        self.issues: Dict[str, Dict[str, Any]] = {}

    def add(self, kind: str, severity: str, detail: str, sample: str = "") -> None:
        entry = self.issues.setdefault(
            kind, {"severity": severity, "count": 0, "detail": detail, "samples": []})
        if severity not in SEV_RANK or SEV_RANK[severity] > SEV_RANK[entry["severity"]]:
            entry["severity"] = severity
        entry["count"] += 1
        if sample and len(entry["samples"]) < 3:
            entry["samples"].append(sample)

    def to_dict(self) -> Dict[str, Any]:
        if self.parse_ok:
            d: Dict[str, Any] = {"exists": True, "parse_ok": True, "records": self.records}
            if self.issues:
                d["issues"] = self.issues
            return d
        d = {"exists": self.exists, "parse_ok": False}
        if self.issues:
            d["issues"] = self.issues
        return d


def _read_json(path: Path) -> Tuple[Any, str]:
    try:
        return json.loads(path.read_text(encoding="utf-8")), ""
    except Exception as e:  # noqa: BLE001 体检必须兜住一切解析异常并如实报告
        return None, "%s: %s" % (type(e).__name__, e)


def _check_events(path: Path, f: _File) -> None:
    """事件表是规则引擎的地基,检查最重:字段/枚举/重复/时序/主档覆盖。"""
    events, err = _read_json(path)
    if err or not isinstance(events, list):
        f.parse_ok = False
        f.add("parse_failed", "error", err or "events_sample.json 不是 JSON 数组")
        return
    f.parse_ok = True
    f.records = len(events)
    seen: set = set()
    last_ts: Dict[str, float] = {}
    uids: set = set()
    for i, e in enumerate(events):
        if not isinstance(e, dict):
            f.add("not_object", "error", "记录不是对象", "第 %d 条" % i)
            continue
        for k in ("uid", "ip", "device_id", "type", "ts"):
            if k not in e or e[k] in (None, ""):
                f.add("missing_field", "error", "缺必填字段 %s" % k, "第 %d 条" % i)
        uid = e.get("uid", "")
        if isinstance(uid, str) and uid:
            uids.add(uid)
        ts = e.get("ts")
        if not isinstance(ts, (int, float)) or isinstance(ts, bool) or ts <= 0:
            f.add("ts_invalid", "error", "ts 非法(须为正数)", "第 %d 条 ts=%r" % (i, ts))
        et = e.get("type")
        if et not in EVENT_TYPES:
            f.add("unknown_type", "error", "未知事件类型", "第 %d 条 type=%r" % (i, et))
        amount = e.get("amount")
        if amount is not None and (not isinstance(amount, (int, float))
                                   or isinstance(amount, bool) or amount < 0):
            f.add("amount_invalid", "error", "amount 非法(须为非负数)", "第 %d 条" % i)
        key = (uid, et, ts)
        if uid and key in seen:
            f.add("dup_event", "error", "(uid,type,ts) 重复", "第 %d 条 %s" % (i, key))
        seen.add(key)
        if isinstance(ts, (int, float)) and uid:
            prev = last_ts.get(uid)
            if prev is not None and ts < prev:
                f.add("ts_out_of_order", "warning", "同 uid 事件时间乱序",
                      "%s: %s -> %s" % (uid, prev, ts))
            last_ts[uid] = max(prev, ts) if prev is not None else ts
    # 主档覆盖率:R004/R005 依赖 accounts,缺失会让这两条规则静默失效
    accounts, aerr = _read_json(data_dir() / "accounts.json")
    if not aerr and isinstance(accounts, dict):
        master = {k for k in accounts if not k.startswith("_")}
        missing = sorted(uids - master)
        if missing:
            f.add("master_missing", "warning", "事件 uid 在主档缺失(R004/R005 静默失效)",
                  "缺 %d 个,如 %s" % (len(missing), missing[:3]))
    labels, lerr = _read_json(data_dir() / "labels.json")
    if not lerr and isinstance(labels, dict):
        labeled = {k for k in labels if not k.startswith("_")}
        if len(labeled) < len(uids):
            f.add("label_coverage", "note", "标签未覆盖全部 uid(回测覆盖率口径)",
                  "%d/%d" % (len(labeled), len(uids)))


def _check_blacklist(path: Path, f: _File) -> None:
    records, err = _read_json(path)
    if err or not isinstance(records, list):
        f.parse_ok = False
        f.add("parse_failed", "error", err or "blacklist.json 不是 JSON 数组")
        return
    f.parse_ok = True
    f.records = len(records)
    seen: set = set()
    for i, r in enumerate(records):
        if not isinstance(r, dict):
            f.add("not_object", "error", "记录不是对象", "第 %d 条" % i)
            continue
        for k in ("dimension", "value", "list"):
            if k not in r or r[k] in (None, ""):
                f.add("missing_field", "error", "缺必填字段 %s" % k, "第 %d 条" % i)
        if r.get("dimension") not in DIMENSIONS:
            f.add("unknown_dimension", "error", "未知名单维度", "第 %d 条" % i)
        if r.get("list") not in LIST_COLORS:
            f.add("unknown_color", "error", "未知名单颜色", "第 %d 条 %r" % (i, r.get("list")))
        exp = r.get("expires_at")
        if exp is not None and not (isinstance(exp, str) and DATE_RE.match(exp)):
            f.add("expires_format", "warning", "expires_at 格式非 YYYY-MM-DD",
                  "第 %d 条 %r" % (i, exp))
        key = (r.get("dimension"), r.get("value"), r.get("list"))
        if all(k is not None for k in key) and key in seen:
            f.add("dup_record", "error", "(dimension,value,list) 重复", "第 %d 条" % i)
        seen.add(key)


def _check_accounts(path: Path, f: _File) -> None:
    accts, err = _read_json(path)
    if err or not isinstance(accts, dict):
        f.parse_ok = False
        f.add("parse_failed", "error", err or "accounts.json 不是 JSON 对象")
        return
    f.parse_ok = True
    body = {k: v for k, v in accts.items() if not k.startswith("_")}
    f.records = len(body)
    for k, v in body.items():
        if not isinstance(v, dict):
            f.add("not_object", "error", "账号值不是对象", k)
            continue
        score = v.get("register_risk_score")
        if score is not None and (not isinstance(score, (int, float))
                                  or isinstance(score, bool) or not 0 <= score <= 100):
            f.add("score_out_of_range", "warning", "register_risk_score 越界", k)
        reg = v.get("registered_at")
        if reg is not None and (not isinstance(reg, (int, float)) or isinstance(reg, bool)):
            f.add("registered_at_invalid", "warning", "registered_at 非法", k)


def _check_labels(path: Path, f: _File) -> None:
    labels, err = _read_json(path)
    if err or not isinstance(labels, dict):
        f.parse_ok = False
        f.add("parse_failed", "error", err or "labels.json 不是 JSON 对象")
        return
    f.parse_ok = True
    body = {k: v for k, v in labels.items() if not k.startswith("_")}
    f.records = len(body)
    for k, v in body.items():
        if not isinstance(v, dict) or v.get("label") not in ("fraud", "normal"):
            f.add("label_invalid", "error", "label 必须为 fraud/normal", k)


def _check_thresholds(path: Path, f: _File) -> None:
    versions, err = _read_json(path)
    if err or not isinstance(versions, list):
        f.parse_ok = False
        f.add("parse_failed", "error", err or "thresholds.json 不是 JSON 数组")
        return
    f.parse_ok = True
    f.records = len(versions)
    prev_v, prev_from = None, None
    for i, v in enumerate(versions):
        if not isinstance(v, dict) or "version" not in v:
            f.add("version_missing", "error", "版本记录缺 version", "第 %d 条" % i)
            continue
        ver, eff = v.get("version"), v.get("effective_from")
        if prev_v is not None and (not isinstance(ver, int) or ver <= prev_v):
            f.add("version_not_monotonic", "error", "version 未严格递增",
                  "第 %d 条 version=%r" % (i, ver))
        if prev_from is not None and isinstance(eff, (int, float)) \
                and eff < prev_from:
            f.add("effective_from_out_of_order", "warning", "effective_from 乱序",
                  "第 %d 条" % i)
        if isinstance(ver, int):
            prev_v = ver
        if isinstance(eff, (int, float)):
            prev_from = eff
        if not isinstance(v.get("values"), dict) or not v["values"]:
            f.add("values_empty", "error", "版本无 values", "第 %d 条" % i)


def _check_intel_files(files: Dict[str, Path], f_map: Dict[str, _File]) -> None:
    for name in ("device_intel.json", "ip_intel.json"):
        path, f = files[name], f_map[name]
        if not path.exists():
            continue  # 可选文件缺失不报错(与主循环口径一致)
        data, err = _read_json(path)
        if err or not isinstance(data, dict):
            f.parse_ok = False
            f.add("parse_failed", "error", err or "%s 不是 JSON 对象" % name)
            continue
        f.parse_ok = True
        body = {k: v for k, v in data.items() if not k.startswith("_")}
        f.records = len(body)
        for k, v in body.items():
            if not isinstance(v, dict):
                f.add("not_object", "error", "记录不是对象", k)
                continue
            if name == "device_intel.json":
                for flag in ("is_emulator", "is_rooted", "hook_detected"):
                    if not isinstance(v.get(flag), bool):
                        f.add("flag_invalid", "warning", "指纹开关 %s 非布尔" % flag, k)
            elif v.get("type") not in IP_TYPES:
                f.add("unknown_ip_type", "warning", "未知 IP 类型", "%s: %r" % (k, v.get("type")))


def _check_simple_lists(files: Dict[str, Path], f_map: Dict[str, _File]) -> None:
    req = {"reports.json": ("report_id", "reported_uid"),
           "appeals.json": ("appeal_id", "uid")}
    for name in ("reports.json", "appeals.json"):
        path, f = files[name], f_map[name]
        data, err = _read_json(path)
        if err or not isinstance(data, list):
            f.parse_ok = False
            f.add("parse_failed", "error", err or "%s 不是 JSON 数组" % name)
            continue
        f.parse_ok = True
        f.records = len(data)
        for i, r in enumerate(data):
            if not isinstance(r, dict):
                f.add("not_object", "error", "记录不是对象", "第 %d 条" % i)
                continue
            for k in req[name]:
                if k not in r or r[k] in (None, ""):
                    f.add("missing_field", "error", "缺必填字段 %s" % k, "第 %d 条" % i)


def _check_decisions(path: Path, f: _File) -> None:
    data, err = _read_json(path)
    if err:
        f.parse_ok = False
        f.add("parse_failed", "error", err)
        return
    decisions = data.get("decisions") if isinstance(data, dict) else data
    if not isinstance(decisions, list):
        f.parse_ok = False
        f.add("parse_failed", "error", "decisions_log 结构非法")
        return
    f.parse_ok = True
    f.records = len(decisions)
    for i, d in enumerate(decisions):
        if not isinstance(d, dict):
            f.add("not_object", "error", "记录不是对象", "第 %d 条" % i)
            continue
        if "uid" not in d:
            f.add("missing_field", "error", "决策缺 uid", "第 %d 条" % i)
        if d.get("action") not in ACTIONS:
            f.add("unknown_action", "warning", "未知处置动作", "第 %d 条 %r" % (i, d.get("action")))


def _check_jsonl(path: Path, f: _File) -> None:
    if not path.exists():
        return
    f.exists = True
    bad = 0
    n = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        n += 1
        try:
            json.loads(line)
        except json.JSONDecodeError:
            bad += 1
    f.parse_ok = bad == 0
    f.records = n
    if bad:
        f.add("corrupt_lines", "error", "jsonl 存在损坏行", "%d/%d" % (bad, n))


@tool(
    name="data_health_check",
    description=(
        "对当前数据集做体检:JSON 解析/必填字段/枚举/重复/乱序/主档覆盖率/"
        "jsonl 损坏行。issue 分 error(硬伤,让规则静默失真)/warning(软伤)。"
        "仅当用户明确要求体检或刚换数据集时调用;团伙/日报/账号调查/阈值"
        "what-if 不要以本工具开头。summary=ok 后查账号用 account_profile,"
        "不要再拆 blacklist_query 或重复调用 ip_intel。"
        "account_profile 已返回双 false 时不要用本工具解释查无。"
    ),
    parameters={"type": "object", "properties": {}},
)
def data_health_check():
    d = data_dir()
    f_map: Dict[str, _File] = {}
    issues_total = 0
    errors = 0
    warnings = 0
    notes = 0

    files: Dict[str, Path] = {}
    for name in REQUIRED_JSON_FILES + OPTIONAL_JSON_FILES + JSONL_FILES:
        files[name] = d / name
        f_map[name] = _File()

    for name in REQUIRED_JSON_FILES:
        f = f_map[name]
        f.exists = files[name].exists()
        if not f.exists:
            f.add("file_missing", "error", "必需文件缺失")
        elif name == "events_sample.json":
            _check_events(files[name], f)
        elif name == "blacklist.json":
            _check_blacklist(files[name], f)

    for name in OPTIONAL_JSON_FILES:
        f = f_map[name]
        f.exists = files[name].exists()
        if not f.exists:
            continue  # 可选文件缺失不报错,对应能力自动降级
        if name == "accounts.json":
            _check_accounts(files[name], f)
        elif name == "labels.json":
            _check_labels(files[name], f)
        elif name == "thresholds.json":
            _check_thresholds(files[name], f)
        elif name in ("reports.json", "appeals.json"):
            _check_simple_lists(files, f_map)
        elif name == "decisions_log.json":
            _check_decisions(files[name], f)
        elif name == "pending_actions.json":
            data, err = _read_json(files[name])
            f.parse_ok = err == "" and isinstance(data, list)
            f.records = len(data) if isinstance(data, list) else 0
            if err:
                f.add("parse_failed", "error", err)

    _check_intel_files(files, f_map)
    for name in JSONL_FILES:
        _check_jsonl(files[name], f_map[name])

    file_reports = {}
    for name, f in f_map.items():
        if not f.exists and not f.issues and name not in REQUIRED_JSON_FILES:
            continue  # 可选文件不存在且无 issue 时省略,减噪
        rep = f.to_dict()
        file_reports[name] = rep
        for issue in (rep.get("issues") or {}).values():
            issues_total += issue["count"]
            if issue["severity"] == "error":
                errors += issue["count"]
            elif issue["severity"] == "warning":
                warnings += issue["count"]
            else:
                notes += issue["count"]

    summary = "fail" if errors else ("warn" if warnings else "ok")
    return {
        "dataset": str(d),
        "summary": summary,
        "issues_total": issues_total,
        "errors": errors,
        "warnings": warnings,
        "notes": notes,
        "files": file_reports,
    }
