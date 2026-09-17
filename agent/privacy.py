# -*- coding: utf-8 -*-
"""脱敏层(⑦):敏感标识符不出程序边界。

部署红线:uid/IP/设备号发给公有云 LLM = 敏感数据出公司。本层在 LLM 边界
做双向替换 —— 出去的一律换成 HMAC token(UID_xxx / IP_xxx /
DEV_xxx),回来的 token 再反解成真值执行/展示。LLM 全程只见 token,
但 token 是确定性的(同值同 token),跨轮推理与关联不受影响。

四个替换点(core.Agent.ask,默认启用,FK_PRIVACY=0 才关闭):
  用户输入 -> tokenize -> LLM;LLM 的工具参数 -> detokenize -> dispatch;
  工具结果 -> tokenize -> 对话历史;最终回答 -> detokenize -> 展示。

识别用模式匹配(本骨架的 ID 形态);接真实数据时把 _PATTERNS 换成公司
ID 规范(uid 位数/设备指纹格式/内网段豁免等)。边界断言用 lookaround
而非 \\b:中文与 ID 直接相邻("账号u_1002")时 \\b 会失配。

前后边界只排除字母数字、**不排除下划线**:系统自产的文件名把 ID 拼在
下划线后("timeline_u_1002.png"),排除下划线会让这些真实 uid 漏脱敏 ——
而工具结果里同一 uid 的独立字段已被换成 token,LLM 反而能对照还原映射。
IP 尾断言只排除数字、不排除点号:排除点号时句尾 IP("...203.0.113.66.")
会整段失配泄漏。宁可多脱敏(把版本号误当 IP)也不能漏。
"""
import ipaddress
import hashlib
import hmac
import os
import re
from typing import Any, Dict, List, Optional, Tuple

_PATTERNS: List[Tuple[str, "re.Pattern"]] = [
    ("DEV", re.compile(r"(?<![A-Za-z0-9])(?:g_)?dev_[A-Za-z0-9_]+")),
    ("UID", re.compile(r"(?<![A-Za-z0-9])(?:u_\d+|g_(?:norm|bot|ring|stl|rpt)_[A-Za-z0-9_]+)")),
    # 2~3 个点号段:除完整 IP 外,ip_intel 的 segment 字段("203.0.113")也是
    # 敏感网段,只匹配 4 段会让 24 位地址信息绕过脱敏出边界。贪婪量词保证
    # 完整 IP 优先整体成 token,不会被拆成"前三段 + 尾段"。
    ("IP", re.compile(r"(?<![\d.])(?:\d{1,3}\.){2,3}\d{1,3}(?!\d)")),
    ("EMAIL", re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![A-Za-z0-9.-])")),
    ("UUID", re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{8}-(?:[A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}(?![A-Fa-f0-9])")),
    ("PHONE", re.compile(r"(?<!\d)(?:\+\d{1,3}[- ]?)?\d{3}[- ]?\d{4}[- ]?\d{4}(?!\d)")),
]

_TOKEN_RE = re.compile(r"(?:UID|IP|DEV|EMAIL|PHONE|UUID|TEXT)_[0-9a-f]{8,16}")

# 结构化工具结果优先按字段名脱敏。正则只能覆盖自由文本,不能把公司的
# 所有账号格式猜全;字段级处理保证 UUID/邮箱/手机号等未知形态也不出边界。
_SENSITIVE_KEY_PREFIX = {
    "accounts": "UID", "ips": "IP", "weak_ips": "IP", "devices": "DEV",
    "uid": "UID", "uids": "UID", "user_id": "UID", "account_id": "UID",
    "reported_uid": "UID", "reporter": "UID", "member_uids": "UID",
    "ip": "IP", "ip_address": "IP", "ip_addresses": "IP",
    "device": "DEV", "device_id": "DEV", "device_ids": "DEV",
    "email": "EMAIL", "phone": "PHONE", "phone_number": "PHONE",
}


class Tokenizer:
    """确定性双向替换。salt 默认每进程随机(token 不可跨进程逆推);
    需要跨进程稳定映射时显式传入 salt。"""

    def __init__(self, salt: str = None):
        self._salt = salt if salt is not None else os.urandom(8).hex()
        self._fwd: Dict[str, str] = {}
        self._rev: Dict[str, str] = {}

    def _token(self, prefix: str, value: str) -> str:
        if value not in self._fwd:
            # HMAC 防止 token 被离线字典反推;64-bit 输出比旧 32-bit token
            # 显著降低大规模账号下的碰撞概率。若仍碰撞则带计数器重算,
            # 绝不能静默覆盖 _rev 后把工具调用还原到另一个账号。
            counter = 0
            while True:
                msg = value if counter == 0 else "%s#%d" % (value, counter)
                digest = hmac.new(self._salt.encode("utf-8"), msg.encode("utf-8"),
                                  hashlib.sha256).hexdigest()[:16]
                token = "%s_%s" % (prefix, digest)
                previous = self._rev.get(token)
                if previous is None or previous == value:
                    break
                counter += 1
            self._fwd[value] = token
            self._rev[token] = value
        return self._fwd[value]

    def tokenize(self, text: str) -> str:
        def ipv6(match):
            value = match.group(0)
            try:
                ipaddress.IPv6Address(value)
            except ValueError:
                return value
            return self._token("IP", value)
        text = re.sub(r"(?<![\w:])[0-9a-fA-F:]*:[0-9a-fA-F:.]+(?:%[\w]+)?(?![\w:])", ipv6, text)
        for prefix, pattern in _PATTERNS:
            text = pattern.sub(lambda m, p=prefix: self._token(p, m.group(0)), text)
        return text

    def detokenize(self, text: str) -> str:
        return _TOKEN_RE.sub(lambda m: self._rev.get(m.group(0), m.group(0)), text)

    def tokenize_data(self, obj: Any, key: Optional[str] = None) -> Any:
        """递归脱敏结构化数据;不修改调用方对象。"""
        normalized = (key or "").lower()
        prefix = _SENSITIVE_KEY_PREFIX.get(normalized)
        if prefix is None and normalized.endswith(("_uid", "_user_id", "_account_id")):
            prefix = "UID"
        elif prefix is None and normalized.endswith(("_device_id", "_device_ids")):
            prefix = "DEV"
        elif prefix is None and normalized.endswith(("_ip", "_ip_address")):
            prefix = "IP"
        if normalized in ("source", "target") and isinstance(obj, (list, tuple)) and len(obj) == 2:
            dimension, value = obj
            if dimension in ("uid", "device_id", "ip"):
                return [dimension, self._token(_SENSITIVE_KEY_PREFIX[dimension], str(value))]
        if normalized == "blacklist_hits" and isinstance(obj, str):
            match = re.fullmatch(r"(uid|device_id|ip)=(.*)\((black|gray|white)\)", obj)
            if match:
                dimension, value, label = match.groups()
                return "%s=%s(%s)" % (dimension, self._token(_SENSITIVE_KEY_PREFIX[dimension], value), label)
            return "[unrecognized list evidence withheld]"
        if prefix and isinstance(obj, (str, int, float)) and not isinstance(obj, bool):
            return self._token(prefix, str(obj))
        if isinstance(obj, dict):
            if obj.get("dimension") in ("uid", "device_id", "ip") and "value" in obj:
                obj = dict(obj)
                obj["value"] = self._token(_SENSITIVE_KEY_PREFIX[obj["dimension"]], str(obj["value"]))
            mapping_prefix = {"known_labels": "UID", "per_account": "UID",
                              "device_flags": "DEV"}.get(normalized)
            return {(self._token(mapping_prefix, str(k)) if mapping_prefix else self.tokenize(str(k))):
                    self.tokenize_data(v, str(k)) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.tokenize_data(v, key) for v in obj]
        if isinstance(obj, tuple):
            return [self.tokenize_data(v, key) for v in obj]
        return self.tokenize(obj) if isinstance(obj, str) else obj


    def project_tool_result(self, name, obj):
        """Project through the closed, reviewed output contract for every tool."""
        from .result_schemas import project
        return project(self, name, obj)


def privacy_enabled() -> bool:
    """默认开启；仅显式 FK_PRIVACY=0/false/off/no 才关闭。"""
    raw = os.environ.get("FK_PRIVACY")
    if raw is None:
        return True
    return raw.strip().lower() not in ("0", "false", "off", "no")
