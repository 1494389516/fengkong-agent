# -*- coding: utf-8 -*-
"""DeepSeek API 客户端封装(OpenAI 兼容协议)。

api_key 读取优先级:环境变量 DEEPSEEK_API_KEY > config.yaml 里的 api_key。
建议只用环境变量,避免 key 落盘进 git。
"""
import os
import ipaddress
from pathlib import Path
from urllib.parse import urlparse

import yaml
from openai import OpenAI

ROOT = Path(__file__).resolve().parent.parent


def _resolved_base_url(cfg):
    base_url = cfg.get("base_url", "https://api.deepseek.com").rstrip("/")
    # strict beta 只是 DeepSeek 公网端点的约定;不能因 strict_mode
    # 把用户配置的私有 OpenAI-compatible 端点悄悄改成公网。
    if cfg.get("strict_mode") and urlparse(base_url).hostname == "api.deepseek.com":
        return "https://api.deepseek.com/beta"
    return base_url


def _private_endpoint(url):
    host = (urlparse(url).hostname or "").lower()
    if host == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def load_config():
    with open(ROOT / "config.yaml", "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    cfg["api_key"] = os.environ.get("DEEPSEEK_API_KEY", cfg.get("api_key", ""))
    if not cfg["api_key"]:
        raise RuntimeError("未配置 API key:请 export DEEPSEEK_API_KEY=sk-... 或写入 config.yaml")
    from .privacy import privacy_enabled
    endpoint = _resolved_base_url(cfg)
    if (not privacy_enabled() and not _private_endpoint(endpoint)
            and os.environ.get("FK_ALLOW_INSECURE_LLM") != "1"):
        raise RuntimeError(
            "拒绝启动:公网 LLM 端点必须开启脱敏;"
            "请移除 FK_PRIVACY=0,或仅在受控测试中同时设置 "
            "FK_ALLOW_INSECURE_LLM=1")
    return cfg


def make_client(cfg):
    base_url = _resolved_base_url(cfg)
    # 生产加固:裸调 OpenAI SDK 一次超时/网络抖动就会挂掉整个值班流程,
    # 超时与重试次数从 config 读、带兜底,不做硬编码。
    timeout = float(cfg.get("timeout", 60))
    if timeout <= 0:
        timeout = 60.0
    max_retries = int(cfg.get("max_retries", 3))
    if max_retries < 0:
        max_retries = 3
    return OpenAI(
        api_key=cfg["api_key"],
        base_url=base_url,
        timeout=timeout,
        max_retries=max_retries,
    )
