# -*- coding: utf-8 -*-
"""特征离线/在线一致性校验(P0-5):Training-Serving Skew 的骨架防线。

问题:特征目录/特征版本化保证的是"语义一致";真实线上还必须验证"同一个
(uid, as_of, window) 在离线实现(建模/回测)与在线实现(特征服务)下得到
同一份特征" —— 否则模型离线评估一切正常,线上特征对不上,全部评估都是
假的(经典 training-serving skew)。

设计:
  - 离线路径 = featurelib.account_features(单一事实源,建模与规则同源);
  - 在线路径 = FK_FEATURE_ONLINE_MODULE="module:function" 注入的在线特征
    实现(接真实系统时指向特征服务客户端);未配置时默认与离线同源并
    显式标注 source="same_impl" —— 骨架阶段诚实声明"尚未验证",不假装;
  - 逐字段严格比对(数值/字符串/列表全等),差异清单 + 通过率 + ok/warn/fail。
比较时排除元数据键(uid/found/as_of_ts/window_seconds),只比特征本体。
"""
import importlib
import os
from typing import Dict, List, Optional

from . import tool
from .datasource import load_events, load_labels
from .featurelib import account_features

# 在线特征实现注入点:格式 "package.module:function",签名与
# account_features 一致 (uid, as_of_ts=None, window_seconds=None) -> dict。
# 未配置 = 未验证(与离线同源,结果恒一致但必须诚实标注)。
ONLINE_IMPL_ENV = "FK_FEATURE_ONLINE_MODULE"

_META_KEYS = ("uid", "found", "as_of_ts", "window_seconds")


def _load_online_impl():
    spec = os.environ.get(ONLINE_IMPL_ENV, "")
    if not spec:
        return None
    if ":" not in spec:
        raise ValueError("%s 格式须为 module:function,收到 %r"
                         % (ONLINE_IMPL_ENV, spec))
    mod_name, fn_name = spec.rsplit(":", 1)
    mod = importlib.import_module(mod_name)
    return getattr(mod, fn_name)


def _account_last_ts(uid: str) -> Optional[float]:
    evs = load_events()
    ts = [e["ts"] for e in evs if e["uid"] == uid]
    return max(ts) if ts else None


@tool(
    name="feature_parity_check",
    description=(
        "特征离线/在线一致性校验(Training-Serving Skew 防线):对指定账号,"
        "比较离线实现(featurelib 单一事实源)与在线实现(FK_FEATURE_ONLINE_"
        "MODULE 注入;未配置时同源并显式标注未验证)在同一个 (uid, as_of, "
        "window) 下的特征输出。逐字段严格比对,差异清单 + 通过率。"
        "建模/回测/策略分析前跑一次,线上特征对不上时所有模型评估都是假的。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "uids": {"type": "array", "items": {"type": "string"},
                     "description": "限定账号(可空=全部已标注账号)"},
            "as_of_ts": {"type": "number",
                         "description": "取证时点(可空=各账号最后事件 ts)"},
            "window_seconds": {"type": "integer",
                               "description": "时间窗(可空=全历史)"},
        },
    },
)
def feature_parity_check(uids: List[str] = None, as_of_ts: float = None,
                         window_seconds: int = None):
    labels = load_labels()
    target = list(uids) if uids else sorted(labels.keys())
    online_impl = _load_online_impl()
    source = ("online_impl" if online_impl else "same_impl")
    diffs: List[Dict] = []
    checked = 0
    for uid in target:
        as_of = as_of_ts if as_of_ts is not None else _account_last_ts(uid)
        off = account_features(uid, as_of_ts=as_of, window_seconds=window_seconds)
        if online_impl:
            on = online_impl(uid, as_of_ts=as_of, window_seconds=window_seconds)
        else:
            on = off  # 未注入在线实现:同源(诚实标注,不是验证)
        if not isinstance(on, dict):
            diffs.append({"uid": uid, "key": "<impl>",
                          "offline": "dict", "online": type(on).__name__})
            continue
        checked += 1
        keys = sorted(set(off) | set(on))
        for k in keys:
            if k in _META_KEYS:
                continue
            if off.get(k) != on.get(k):
                diffs.append({"uid": uid, "key": k,
                              "offline": off.get(k), "online": on.get(k)})
    failed_uids = sorted({d["uid"] for d in diffs})
    verdict = "ok"
    if diffs:
        verdict = "fail"
    elif not online_impl:
        verdict = "warn"  # 同源恒一致,不等于线上已验证
    return {
        "checked": checked,
        "passed": checked - len(failed_uids),
        "failed_accounts": failed_uids,
        "diff_count": len(diffs),
        "diffs": diffs[:20],
        "source": source,
        "online_impl": os.environ.get(ONLINE_IMPL_ENV, "") or None,
        "verdict": verdict,
        "note": ("" if online_impl else
                 "未配置 FK_FEATURE_ONLINE_MODULE:离线/在线同源,通过不代表"
                 "线上特征已验证 —— 接真实特征服务后重跑才有验证意义"),
    }
