# -*- coding: utf-8 -*-
"""引擎模式查询:agent 判定走生产引擎 dry-run 还是本地降级备份。

唯一引擎纪律:agent 下结论前应先知道自己的判定来自哪里 —— 配置了
FK_ENGINE_DRYRUN_URL 时判定来自生产引擎,本地 R001-R006 只是备份;
未配置时(骨架默认)判定全部来自本地实现。
"""
from typing import Any, Dict

from . import tool
from ..engine import engine_status as _engine_status


@tool(
    name="engine_status",
    description=(
        "查询规则判定的来源通道:remote_engine(生产引擎 dry-run)/ "
        "local_rules(本地备份)。附 circuit(粘滞熔断状态)。"
        "rule_eval 返回的 source 字段与之对应。"
    ),
    parameters={"type": "object", "properties": {}},
)
def engine_status() -> Dict[str, Any]:
    return _engine_status()
