# -*- coding: utf-8 -*-
"""值班台操作:关注清单 + 告警确认,治监控的"告警疲劳"。

监控系统的头号死因不是漏报是重复报:daily_brief 每天把同一条告警原样再报
一遍,一周后没人再看它 —— 狼来了。两个机制:
- 告警确认(ack):研究员看过的告警按指纹静默,日报不再重复;但只静默
  "同等严重度"—— 指标再恶化超过确认时的 1.25 倍立刻重新浮出(escalated)。
  确认不是关闭:acked 计数始终在日报里,没有告警会无声消失。
- 关注清单(watch):调查中的账号/资源挂上 watch,日报单列它们的当前判定
  与命中规则 —— 值班的"盯梢"语义,与灰名单(处置观察态)不同,watch 是
  研究侧的便签,不影响任何判定。

写权限边界:watch/ack 是研究员的工作台状态,不是处置(不改名单/阈值/
标签),因此直接生效不走审批 —— 但每次操作追加审计日志,可回溯谁静默了
什么。防呆:ack 只能按日报里真实出现过的告警文本做指纹,不能凭空静默。
"""
import json
import re
from typing import Dict, List, Optional

from . import tool
from .datasource import alert_acks_path, audit_log_path, watchlist_path

VALID_DIMENSIONS = ("uid", "ip", "device_id")


def _load(path) -> List[Dict]:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else []


def _save(path, items: List[Dict]) -> None:
    from .datasource import atomic_write_json
    atomic_write_json(path, items)


def _audit(entry: Dict) -> None:
    from .actions import _now_iso
    from .datasource import append_jsonl
    append_jsonl(audit_log_path(), {"ts": _now_iso(), "decision": "duty_ops", **entry})


def alarm_fingerprint(alarm: str) -> str:
    """告警指纹:剥掉数字与日期,留下"哪个监控项在报什么"的骨架 ——
    同一问题每天数值微变不该被当成新告警。"""
    return re.sub(r"[\d.,:%\-]+", "#", alarm)


def alarm_severity(alarm: str) -> float:
    """告警严重度:文本里最大的数值(PSI 值/百分比)。用于恶化重浮:
    ack 静默的是"当时那个程度",不是这个问题本身。
    日期/时间和标识符里的数字(2026-07-15、R006、u_1009)不是程度,必须剔除
    —— 否则年份永远是最大数,恶化重浮永远触发不了。"""
    cleaned = re.sub(r"\d{4}-\d{2}-\d{2}", "", alarm)
    cleaned = re.sub(r"\d{1,2}:\d{2}(?::\d{2})?", "", cleaned)
    nums = [float(m) for m in re.findall(r"(?<![\w.])\d+(?:\.\d+)?", cleaned)]
    return max(nums) if nums else 0.0


ESCALATE_RATIO = 1.25  # 严重度超过确认时的 1.25 倍即重新浮出


def filter_acked(alarms: List[str]) -> Dict:
    """把告警列表按确认状态分流:active(未确认/已恶化)与 acked 计数。
    daily_brief 用它 —— 逻辑放这边,确认语义只实现一次。"""
    acks = {a["fingerprint"]: a for a in _load(alert_acks_path())}
    active, acked, escalated = [], 0, []
    for alarm in alarms:
        ack = acks.get(alarm_fingerprint(alarm))
        if ack is None:
            active.append(alarm)
        elif alarm_severity(alarm) > ack.get("severity", 0.0) * ESCALATE_RATIO:
            escalated.append(alarm + "(已确认过但恶化,重新浮出)")
        else:
            acked += 1
    return {"active": active + escalated, "acked_count": acked,
            "escalated_count": len(escalated)}


@tool(
    name="duty_ops",
    description=(
        "值班台:watch_add/watch_remove 维护关注清单(盯梢对象在日报单列,不影响"
        "判定);ack_alarm 确认日报告警(按指纹静默,恶化自动重浮,计数可见);"
        "list 查看两者。直接生效但全程审计。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "action": {"type": "string",
                       "enum": ["watch_add", "watch_remove", "ack_alarm", "list"]},
            "dimension": {"type": "string", "enum": list(VALID_DIMENSIONS)},
            "value": {"type": "string", "description": "watch_* 用:关注对象"},
            "alarm": {"type": "string", "description": "ack_alarm 用:日报告警原文"},
            "reason": {"type": "string", "description": "理由,进审计"},
        },
        "required": ["action"],
    },
)
def duty_ops(action: str, dimension: Optional[str] = None, value: Optional[str] = None,
             alarm: Optional[str] = None, reason: str = ""):
    if action == "list":
        return {"watchlist": _load(watchlist_path()),
                "acked_alarms": [{k: a[k] for k in ("fingerprint", "acked_at", "reason")
                                  if k in a} for a in _load(alert_acks_path())]}

    if action in ("watch_add", "watch_remove"):
        if dimension not in VALID_DIMENSIONS or not value:
            return {"error": "watch_* 需要 dimension(%s)与 value" % "/".join(VALID_DIMENSIONS)}
        wl = _load(watchlist_path())
        exists = [w for w in wl if w["dimension"] == dimension and w["value"] == value]
        if action == "watch_add":
            if exists:
                return {"status": "already_watching", "entry": exists[0]}
            from .actions import _now_iso
            entry = {"dimension": dimension, "value": value,
                     "reason": reason, "added_at": _now_iso()}
            wl.append(entry)
            _save(watchlist_path(), wl)
            _audit({"kind": "watch_add", "dimension": dimension, "value": value,
                    "reason": reason})
            return {"status": "watching", "entry": entry, "watch_count": len(wl)}
        if not exists:
            return {"status": "not_watching"}
        _save(watchlist_path(),
              [w for w in wl if not (w["dimension"] == dimension and w["value"] == value)])
        _audit({"kind": "watch_remove", "dimension": dimension, "value": value,
                "reason": reason})
        return {"status": "removed", "watch_count": len(wl) - 1}

    if action == "ack_alarm":
        if not alarm:
            return {"error": "ack_alarm 需要 alarm(日报 alerts 里的告警原文)"}
        # 防呆:只允许确认当前日报里真实存在的告警,不能凭空静默一个指纹
        from .brief import daily_brief
        current = []
        for v in daily_brief()["alerts"].values():
            current += v if isinstance(v, list) else [v]
        live = [a for part in current for a in str(part).split(";")]
        if not any(alarm_fingerprint(alarm) == alarm_fingerprint(a) for a in live):
            return {"error": "该告警不在当前日报的 alerts 里,无从确认;先 daily_brief 核对原文"}
        acks = _load(alert_acks_path())
        fp = alarm_fingerprint(alarm)
        acks = [a for a in acks if a["fingerprint"] != fp]
        from .actions import _now_iso
        acks.append({"fingerprint": fp, "severity": alarm_severity(alarm),
                     "alarm": alarm, "reason": reason, "acked_at": _now_iso()})
        _save(alert_acks_path(), acks)
        _audit({"kind": "ack_alarm", "alarm": alarm, "reason": reason})
        return {"status": "acked", "fingerprint": fp,
                "note": "同指纹告警不再进日报;严重度恶化超 %.2f 倍自动重浮" % ESCALATE_RATIO}

    return {"error": "action 必须是 watch_add/watch_remove/ack_alarm/list"}


def watched_status() -> List[Dict]:
    """关注对象的当前状态(daily_brief 的 watched 区):uid 给判定与命中规则,
    资源给共用账号数。"""
    from .backtest import account_verdicts
    from .datasource import load_events
    from .featurelib import accounts_per
    wl = _load(watchlist_path())
    if not wl:
        return []
    events = load_events()
    out = []
    uids = [w["value"] for w in wl if w["dimension"] == "uid"]
    verdicts = account_verdicts(uids, events) if uids else {}
    for w in wl:
        if w["dimension"] == "uid":
            v = verdicts.get(w["value"], {})
            out.append({"watch": "uid=%s" % w["value"],
                        "verdict": v.get("predicted"), "rules": v.get("rules", [])})
        else:
            r = accounts_per(w["dimension"], w["value"])
            out.append({"watch": "%s=%s" % (w["dimension"], w["value"]),
                        "shared_accounts": r["count"]})
    return out
