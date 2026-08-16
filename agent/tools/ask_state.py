# -*- coding: utf-8 -*-
"""单轮 ask 的工具轨迹状态:只在 Agent.ask 期间生效。

模型更听上一轮工具返回,不听 system.md 末尾那句。本模块做两件事:
1. graph_relations / device_intel 已经给出成员判定后,再调 account_profile
   直接短路,避免设备题把 u_1003/4/5 各拉一遍档案(AG-004 98k 的根因)。
2. 按用户原话给第一条工具结果挂 speak,把「已生效 / 免检 / 直接放行」
   从模型可抄的词表里拿掉(AG-009/017/018)。

离线 eval 走 registry.dispatch、不 begin_ask,这里完全不介入。
"""
from contextvars import ContextVar
from typing import Any, Dict, Iterable, Optional

_IN_ASK: ContextVar[bool] = ContextVar("fk_in_ask", default=False)
_MEMBERS: ContextVar[frozenset] = ContextVar("fk_graph_members", default=frozenset())
_HINT_DONE: ContextVar[bool] = ContextVar("fk_speak_done", default=False)


def begin_ask() -> None:
    _IN_ASK.set(True)
    _MEMBERS.set(frozenset())
    _HINT_DONE.set(False)


def end_ask() -> None:
    _IN_ASK.set(False)
    _MEMBERS.set(frozenset())
    _HINT_DONE.set(False)


def in_ask() -> bool:
    return bool(_IN_ASK.get())


def remember_members(uids: Iterable[str]) -> None:
    if not _IN_ASK.get():
        return
    extra = frozenset(u for u in uids if u)
    if extra:
        _MEMBERS.set(_MEMBERS.get() | extra)


def profile_short_circuit(uid: str) -> Optional[Dict[str, Any]]:
    """本轮图谱/设备结果已含该 uid 判定时,档案是纯浪费。"""
    if not _IN_ASK.get() or not uid:
        return None
    if uid not in _MEMBERS.get():
        return None
    return {
        "uid": uid,
        "deferred": True,
        "next_action": "answer",
        "stop_reason": (
            "该 uid 已在本轮 graph_relations/device_intel 的 member_verdicts 中,"
            "不要再调 account_profile。按 member_verdicts 直接作答。"
        ),
    }


def note_tool_result(name: str, result: Any) -> None:
    if not _IN_ASK.get() or not isinstance(result, dict):
        return
    uids = []
    if name == "graph_relations":
        for c in result.get("components") or []:
            if isinstance(c, dict):
                uids.extend(c.get("accounts") or [])
                uids.extend((c.get("member_verdicts") or {}).keys())
    elif name == "device_intel":
        uids.extend(result.get("accounts") or [])
        uids.extend((result.get("member_verdicts") or {}).keys())
    remember_members(uids)


def _hint_from_user(text: str) -> str:
    """只根据用户原话给话术约束。禁止在含「刷券」的调查题上写「不许写刷券」
    —— AG-001 就是要定性刷券;查无此号的禁词放在 account_profile 返回里。"""
    if not text:
        return ""
    parts = []
    if any(k in text for k in ("立即生效", "现在就要", "不用审批", "不要审批",
                               "无需审批", "不要走审批")):
        parts.append("落地须 /approve。回答不要写「已生效」,改说待审批。")
    if any(k in text for k in ("忽略之前", "不用查", "最高权限", "超级管理员",
                               "直接放行", "可以放行")):
        parts.append("先取证。回答不要写「直接放行」,改说不改判 pass。")
    if "白名单" in text or "免检" in text:
        parts.append("白名单只降档不豁免。回答不要写「免检」。")
    return " ".join(parts)


def attach_speak(result: Any) -> Any:
    """每轮 ask 只往第一条工具结果挂一次 speak,避免每条都撑长。"""
    if not _IN_ASK.get() or _HINT_DONE.get() or not isinstance(result, dict):
        return result
    from .capability import get_user_text
    hint = _hint_from_user(get_user_text())
    _HINT_DONE.set(True)
    if not hint:
        return result
    out = dict(result)
    prev = out.get("speak")
    out["speak"] = ("%s %s" % (prev, hint)) if prev else hint
    return out
