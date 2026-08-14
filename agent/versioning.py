# -*- coding: utf-8 -*-
"""Agent 配置版本化:每次运行可回答"AG-017 失败是模型变了、Prompt 变了,
还是工具集变了"。

三个指纹(内容哈希,确定性):
  prompt_version       system.md 内容哈希 —— prompt 一变,值必变;
  toolset_hash         工具 schema 集内容哈希(含描述)—— 工具增删改必变;
  agent_policy_version system + 上下文工程参数(TOOL_KEEP_TURNS 等)哈希
                       —— 上下文参数调整也纳入版本。

每条运行日志(FK_AGENT_RUN_LOG)写入三指纹 + model,与 token/延迟/工具
轨迹放在同一行 —— 评估回归定位"哪一维变了"时,先比版本再比指标。
"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _h16(blob: str) -> str:
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:12]


def system_hash() -> str:
    """system.md 内容哈希(prompt 版本)。"""
    md = (ROOT / "agent" / "prompts" / "system.md").read_text(encoding="utf-8")
    return _h16(md)


def toolset_hash() -> str:
    """工具 schema 集内容哈希(工具集版本)。"""
    from .tools import schemas
    blob = json.dumps(schemas(), ensure_ascii=False, sort_keys=True)
    return _h16(blob)


def agent_policy_version() -> str:
    """system + 上下文工程参数 的内容哈希(agent 策略版本)。"""
    from . import core as _core
    md = (ROOT / "agent" / "prompts" / "system.md").read_text(encoding="utf-8")
    params = json.dumps({
        "TOOL_KEEP_TURNS": _core.TOOL_KEEP_TURNS,
        "CHECKPOINT_EVERY": _core.CHECKPOINT_EVERY,
        "CONTEXT_EST_TOKEN_BUDGET": _core.CONTEXT_EST_TOKEN_BUDGET,
        "MAX_TOOL_ROUNDS": _core.MAX_TOOL_ROUNDS,
    }, sort_keys=True)
    return _h16(md + "|" + params)


def snapshot() -> dict:
    """一次运行使用的完整版本指纹(随运行日志落盘)。"""
    return {
        "prompt_version": system_hash(),
        "toolset_hash": toolset_hash(),
        "agent_policy_version": agent_policy_version(),
    }
