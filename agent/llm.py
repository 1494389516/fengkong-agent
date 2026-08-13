# -*- coding: utf-8 -*-
"""DeepSeek API 客户端封装(OpenAI 兼容协议)。

api_key 读取优先级:环境变量 DEEPSEEK_API_KEY > config.yaml 里的 api_key。
建议只用环境变量,避免 key 落盘进 git。
"""
import os
from pathlib import Path

import yaml
from openai import OpenAI

ROOT = Path(__file__).resolve().parent.parent


def load_config():
    with open(ROOT / "config.yaml", "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    cfg["api_key"] = os.environ.get("DEEPSEEK_API_KEY", cfg.get("api_key", ""))
    if not cfg["api_key"]:
        raise RuntimeError("未配置 API key:请 export DEEPSEEK_API_KEY=sk-... 或写入 config.yaml")
    return cfg


def make_client(cfg):
    base_url = cfg.get("base_url", "https://api.deepseek.com")
    if cfg.get("strict_mode"):
        # strict mode 要求 beta endpoint —— 见 DeepSeek Tool Calls 文档
        base_url = "https://api.deepseek.com/beta"
    return OpenAI(api_key=cfg["api_key"], base_url=base_url)
