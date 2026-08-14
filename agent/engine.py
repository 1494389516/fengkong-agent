# -*- coding: utf-8 -*-
"""引擎适配器:agent 规则判定的唯一入口(唯一事实源纪律的代码化)。

架构军规:风控系统(规则引擎)是唯一事实源,agent 是镜像,镜像必须对账。
因此 agent 的规则判定必须优先走生产引擎的 dry-run 试算接口;本地
R001-R006 实现只是"接真实引擎之前"的骨架替身与"引擎不可用"时的降级
备份 —— 绝不并行维护两套规则口径(两套引擎 = 口径漂移 + 双份维护,
风控经典事故)。

判定路径(每次调用时解析):
  1. policy what-if 覆盖生效 -> 永远本地:覆盖参数是本地模拟概念,
     生产 dry-run 不接收;假想阈值也不该拿去对账。
  2. FK_ENGINE_DRYRUN_URL 配置了远程试算端点 -> 远程 dry-run 优先;
     调用失败 -> 本地降级,并显式打 degraded 标记。不能静默:静默降级
     会让镜像对账变成"本地 vs 本地",口径漂移再次隐身。
  3. 否则 -> 本地规则实现(骨架默认)。

远程契约:POST {"event": {...}, "use_current_policy": bool},期望返回
{"action": "pass|review|reject", "hits": [...], "policy_version": ...,
 "rule_count_evaluated": ...};返回结构与本项目 rule_eval 兼容,并附
source 字段供结论溯源。鉴权:FK_ENGINE_DRYRUN_TOKEN 配置时注入
Authorization: Bearer 头。

批量契约(evaluate_batch,全量工具专用):POST {"events": [...],
"use_current_policy": bool} -> {"decisions": [每事件一个结果]},顺序与
请求对齐。backtest/scan 的 account_verdicts 在远程模式下走这条批量
路径 —— 全量工具绝不逐事件打在线网关(250 账号 = 1 次 POST 而非
N×M 次 HTTP)。
"""
import json
import os
import urllib.request
from typing import Any, Dict, List

DRYRUN_URL_ENV = "FK_ENGINE_DRYRUN_URL"
DRYRUN_TIMEOUT_ENV = "FK_ENGINE_DRYRUN_TIMEOUT"
DRYRUN_TOKEN_ENV = "FK_ENGINE_DRYRUN_TOKEN"


def _overridden() -> bool:
    from .tools.policy import active_policy
    return bool(active_policy()["_overridden"])


def _post_json(url: str, payload: Dict[str, Any],
               headers: Dict[str, str] = None) -> Dict[str, Any]:
    """HTTP POST 传输(拆成独立函数,便于离线测试打桩,不依赖真实网络)。"""
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    token = os.environ.get(DRYRUN_TOKEN_ENV)
    if token:
        hdrs["Authorization"] = "Bearer " + token
    req = urllib.request.Request(
        url,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers=hdrs,
        method="POST",
    )
    timeout = float(os.environ.get(DRYRUN_TIMEOUT_ENV, "10") or 10)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _map_remote(raw: Dict[str, Any]) -> Dict[str, Any]:
    """把引擎 dry-run 的返回映射成本项目 rule_eval 的规范形状(工具层契约)。

    引擎没回 hits 明细时,合成一条 ENGINE 命中保证证据链字段不缺失 ——
    rule_id 用 ENGINE 明确标注"判定来自引擎,本地规则未参与"。
    """
    action = raw.get("action", "pass")
    hits = raw.get("hits")
    if hits is None:
        hits = [{"rule_id": "ENGINE", "reason": "生产引擎 dry-run 判定",
                 "action": action}]
    return {
        "hits": hits,
        "action": action,
        "rule_count_evaluated": raw.get("rule_count_evaluated"),
        "policy_version": raw.get("policy_version"),
        "source": "remote_engine",
    }


def evaluate_event(event: Dict[str, Any],
                   use_current_policy: bool = False) -> Dict[str, Any]:
    """规则判定的唯一入口。返回结构与本地 rule_eval 兼容,附 source 字段
    (local_rules / remote_engine / local_rules_fallback)供溯源。"""
    from .tools.rules import _local_rule_eval  # 惰性:防导入环

    if _overridden():
        r = _local_rule_eval(event, use_current_policy=use_current_policy)
        r["source"] = "local_rules"
        r["source_note"] = ("what-if 覆盖生效,强制本地模拟"
                            "(覆盖参数是本地模拟概念,生产 dry-run 不接收)")
        return r
    url = os.environ.get(DRYRUN_URL_ENV)
    if not url:
        r = _local_rule_eval(event, use_current_policy=use_current_policy)
        r["source"] = "local_rules"
        return r
    try:
        return _map_remote(_post_json(url, {
            "event": event,
            "use_current_policy": bool(use_current_policy),
        }))
    except Exception as e:  # noqa: BLE001
        # 显式降级:结果必须带 degraded/engine_error,让结论可被审计到
        r = _local_rule_eval(event, use_current_policy=use_current_policy)
        r["source"] = "local_rules_fallback"
        r["degraded"] = True
        r["engine_error"] = "%s: %s" % (type(e).__name__, e)
        return r


def evaluate_batch(events: List[Dict[str, Any]],
                   use_current_policy: bool = False) -> List[Dict[str, Any]]:
    """批量判定:全量工具(backtest/scan 的 account_verdicts)在远程模式下
    的唯一形态 —— 一次 POST 覆盖全部事件,顺序与请求对齐。覆盖生效/未配置
    引擎时逐条走本地;远程失败逐条显式降级(degraded,不静默)。"""
    from .tools.rules import _local_rule_eval  # 惰性:防导入环

    if not events:
        return []
    if _overridden() or not os.environ.get(DRYRUN_URL_ENV):
        return [{**_local_rule_eval(e, use_current_policy=use_current_policy),
                 "source": "local_rules"} for e in events]
    try:
        raw = _post_json(os.environ[DRYRUN_URL_ENV], {
            "events": events,
            "use_current_policy": bool(use_current_policy),
        })
        decisions = raw.get("decisions")
        if not isinstance(decisions, list) or len(decisions) != len(events):
            raise ValueError("批量 dry-run 返回与请求不齐(期望 %d 条,得 %r)"
                             % (len(events), type(decisions).__name__))
        return [_map_remote(d) for d in decisions]
    except Exception as e:  # noqa: BLE001
        out = []
        for ev in events:
            r = _local_rule_eval(ev, use_current_policy=use_current_policy)
            r.update({"source": "local_rules_fallback", "degraded": True,
                      "engine_error": "%s: %s" % (type(e).__name__, e)})
            out.append(r)
        return out


def engine_status() -> Dict[str, Any]:
    """当前判定通道:远程 dry-run 还是本地实现。agent 下结论前应先知道
    自己的判定来自哪里(唯一引擎纪律,见 system.md)。"""
    url = os.environ.get(DRYRUN_URL_ENV)
    if not url:
        return {
            "mode": "local_rules",
            "note": ("未配置 FK_ENGINE_DRYRUN_URL:判定来自本地 R001-R006 实现"
                     "(骨架替身/降级备份)。接真实系统后配置生产引擎 dry-run "
                     "端点,本地实现自动降级为备份。"),
        }
    return {
        "mode": "remote_engine",
        "url": url.split("?")[0],  # 不把 query 里的凭据带进结论
        "note": ("远程 dry-run 优先;调用失败自动降级本地并带 degraded/"
                 "engine_error 标记,结论必须声明降级。"),
    }
