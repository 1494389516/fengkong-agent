# -*- coding: utf-8 -*-
"""脱敏层(⑦):敏感标识符不出程序边界。

部署红线:uid/IP/设备号发给公有云 LLM = 敏感数据出公司。本层在 LLM 边界
做双向替换 —— 出去的一律换成不可逆推的 token(UID_xxxxxxxx / IP_xxxxxxxx /
DEV_xxxxxxxx),回来的 token 再反解成真值执行/展示。LLM 全程只见 token,
但 token 是确定性的(同值同 token),跨轮推理与关联不受影响。

四个替换点(core.Agent.ask,FK_PRIVACY=1 时启用):
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
import hashlib
import os
import re
from typing import Dict, List, Tuple

_PATTERNS: List[Tuple[str, "re.Pattern"]] = [
    ("DEV", re.compile(r"(?<![A-Za-z0-9])(?:g_)?dev_[A-Za-z0-9_]+")),
    ("UID", re.compile(r"(?<![A-Za-z0-9])(?:u_\d+|g_(?:norm|bot|ring|stl|rpt)_[A-Za-z0-9_]+)")),
    # 2~3 个点号段:除完整 IP 外,ip_intel 的 segment 字段("203.0.113")也是
    # 敏感网段,只匹配 4 段会让 24 位地址信息绕过脱敏出边界。贪婪量词保证
    # 完整 IP 优先整体成 token,不会被拆成"前三段 + 尾段"。
    ("IP", re.compile(r"(?<![\d.])(?:\d{1,3}\.){2,3}\d{1,3}(?!\d)")),
]

_TOKEN_RE = re.compile(r"(?:UID|IP|DEV)_[0-9a-f]{8}")


class Tokenizer:
    """确定性双向替换。salt 默认每进程随机(token 不可跨进程逆推);
    需要跨进程稳定映射时显式传入 salt。"""

    def __init__(self, salt: str = None):
        self._salt = salt if salt is not None else os.urandom(8).hex()
        self._fwd: Dict[str, str] = {}
        self._rev: Dict[str, str] = {}

    def _token(self, prefix: str, value: str) -> str:
        if value not in self._fwd:
            digest = hashlib.sha1((self._salt + value).encode("utf-8")).hexdigest()[:8]
            token = "%s_%s" % (prefix, digest)
            self._fwd[value] = token
            self._rev[token] = value
        return self._fwd[value]

    def tokenize(self, text: str) -> str:
        for prefix, pattern in _PATTERNS:
            text = pattern.sub(lambda m, p=prefix: self._token(p, m.group(0)), text)
        return text

    def detokenize(self, text: str) -> str:
        return _TOKEN_RE.sub(lambda m: self._rev.get(m.group(0), m.group(0)), text)


def privacy_enabled() -> bool:
    return os.environ.get("FK_PRIVACY", "") == "1"
