# -*- coding: utf-8 -*-
"""工具注册表:工具模块用 @tool 装饰器自注册,core.py 据此生成 schema 并调度。

新增工具只需:在本目录建一个 .py 文件,用 @tool 装饰处理函数,
然后把模块名加进文件底部的 import 行。
"""
from typing import Any, Callable, Dict, List

_REGISTRY: Dict[str, Dict[str, Any]] = {}

# ② 工具限幅:工具结果是 token 爆炸的最大来源(一次 feature_stats 可能拖出上百个 ip/设备)。
#   dispatch 是所有工具结果回填进对话前的单点,在这里递归截断,一处生效全局。
MAX_LIST_ITEMS = 20   # 长列表只留前 N 项 + 一条计数说明
MAX_STR_LEN = 800     # 超长字符串截断


def _cap(obj: Any) -> Any:
    """递归限幅:长列表留前 N + "共 X 条",超长字符串截断。保留结构让模型仍能解析。"""
    if isinstance(obj, list):
        capped = [_cap(x) for x in obj[:MAX_LIST_ITEMS]]
        if len(obj) > MAX_LIST_ITEMS:
            capped.append({"_truncated": "共 %d 条,已省略 %d 条" % (len(obj), len(obj) - MAX_LIST_ITEMS)})
        return capped
    if isinstance(obj, dict):
        return {k: _cap(v) for k, v in obj.items()}
    if isinstance(obj, str) and len(obj) > MAX_STR_LEN:
        return obj[:MAX_STR_LEN] + "…[已截断,原长 %d 字符]" % len(obj)
    return obj


def tool(name: str, description: str, parameters: Dict[str, Any]) -> Callable:
    """注册工具。parameters 是 JSON Schema(OpenAI/DeepSeek function calling 格式)。"""
    def decorator(fn: Callable) -> Callable:
        _REGISTRY[name] = {"fn": fn, "description": description, "parameters": parameters}
        return fn
    return decorator


def schemas() -> List[Dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {
                "name": name,
                "description": t["description"],
                "parameters": t["parameters"],
            },
        }
        for name, t in _REGISTRY.items()
    ]


def dispatch(name: str, arguments: Dict[str, Any]) -> Any:
    """执行工具。异常不上抛,包成 error 返回给模型,让它自行调整。"""
    if name not in _REGISTRY:
        return {"error": "unknown tool: %s" % name}
    try:
        return _cap(_REGISTRY[name]["fn"](**arguments))  # ② 结果回填前统一限幅
    except Exception as e:  # noqa: BLE001
        return {"error": "%s: %s" % (type(e).__name__, e)}


# 导入即注册(注意顺序:rules 依赖 blacklist/features;backtest 依赖 rules;
# charts 依赖 backtest;monitor 依赖 blacklist)
from . import blacklist, features, rules, backtest, monitor, charts  # noqa: E402,F401
