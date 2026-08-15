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

Decision Plane 接入(P0-2/P0-3,骨架的"治理 -> 判定"打通):
  - active strategy:strategy registry 里 status=active 的策略,其阈值覆盖
    真正进入本地判定(函数级参数,线程安全);远程模式下版本号随请求带出,
    判定由生产引擎负责(本地 registry 是治理镜像);
  - champion 模型:R007 模型信号 —— champion 风险分过 model_score_*_threshold
    (policy 版本表,默认 0.9/0.98 = 关闭)即命中;分数来源 FK_ENGINE_MODEL_URL
    或本地 data/model_scores.json(骨架模拟模型服务)。无 champion/无分数
    = 无信号,判定不变。
"""
import json
import os
import urllib.request
from typing import Any, Dict, List

DRYRUN_URL_ENV = "FK_ENGINE_DRYRUN_URL"
DRYRUN_TIMEOUT_ENV = "FK_ENGINE_DRYRUN_TIMEOUT"
DRYRUN_TOKEN_ENV = "FK_ENGINE_DRYRUN_TOKEN"
# P0-2 模型服务端点(可选):POST {"uid","event"} -> {"score": 0~1}。
# 未配置时走本地 data/model_scores.json(骨架模拟模型服务)。
MODEL_URL_ENV = "FK_ENGINE_MODEL_URL"


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


def _active_strategy() -> Dict:
    """当前 active strategy 的阈值覆盖(治理元数据 -> 判定, P0-3)。

    strategy registry 是治理层:同名同时只有一个 active;其阈值覆盖在此
    真正进入判定路径(本地模式经函数级参数传给规则实现,线程安全)。
    无 active / 文件缺失 -> 空覆盖(行为与接入前完全一致)。
    远程引擎模式:阈值由生产配置中心下发,本地 registry 是治理镜像 ——
    判定以引擎为准,这里只把版本号带进血缘。
    """
    from .tools.strategy_registry import _load as _sload  # 惰性:防导入环
    try:
        actives = [s for s in _sload() if s.get("status") == "active"]
    except Exception:  # noqa: BLE001 注册表损坏不掀翻判定路径
        return {}
    if not actives:
        return {}
    # 不同名策略各自允许一个 active;判定只能有一套生效阈值 —— 取部署时间
    # 最新的 active 并显式标注歧义,不静默选第一个(顺序取决于文件写入序,
    # 语义上是随机的)。生产应由配置中心路由到单一策略,这里兜底确定性。
    actives.sort(key=lambda s: (s.get("deployed_at") or "",
                                s["strategy_name"], s["version"]))
    s = actives[-1]
    out = {
        "strategy_version": "%s %s" % (s["strategy_name"], s["version"]),
        "strategy_thresholds": s.get("thresholds") or {},
    }
    if len(actives) > 1:
        out["strategy_ambiguity"] = (
            "存在 %d 个 active 策略,取部署时间最新的 %s;其余 %s"
            % (len(actives), out["strategy_version"],
               ", ".join("%s %s" % (x["strategy_name"], x["version"])
                         for x in actives[:-1])))
    return out


def _champion() -> Dict:
    """当前 champion 模型(唯一)。无则返回 {}。"""
    from .tools.model_registry import _load as _mload  # 惰性:防导入环
    try:
        ch = [m for m in _mload() if m.get("status") == "champion"]
    except Exception:  # noqa: BLE001 登记簿损坏不掀翻判定路径
        return {}
    return ch[0] if ch else {}


def _model_score_local(uid: str):
    """本地模型分数(骨架模拟模型服务):data/model_scores.json {uid: score}。
    这是离线实验/影子阶段的注入点,接真实系统后由 FK_ENGINE_MODEL_URL
    的模型服务取代。文件缺失或 uid 无分 -> None(无模型信号)。"""
    from .tools.datasource import data_dir  # 惰性
    import json as _j
    p = data_dir() / "model_scores.json"
    try:
        data = _j.loads(p.read_text(encoding="utf-8"))
    except (OSError, _j.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    s = data.get(uid)
    return float(s) if s is not None else None


def _model_score_remote(uid: str, event: Dict[str, Any]):
    """远程模型服务(FK_ENGINE_MODEL_URL):POST {"uid","event"} ->
    {"score": 0~1}。失败显式返回 None(无模型信号,不静默拦截/放行)。"""
    url = os.environ.get(MODEL_URL_ENV)
    if not url:
        return None
    try:
        raw = _post_json(url, {"uid": uid, "event": event})
        s = raw.get("score")
        return float(s) if s is not None else None
    except Exception:  # noqa: BLE001 模型服务失败 = 模型信号缺失,规则照常
        return None


def _apply_model_signal(result: Dict[str, Any], event: Dict[str, Any],
                        use_current_policy: bool = False) -> Dict:
    """R007 模型信号(P0-2):champion 模型真正进入判定路径。

    - 无 champion -> 判定不变(只可能随 champion 上线才生效);
    - 有 champion 无分数 -> 附 model_version 血缘,不命中(诚实:模型在
      观察位,没有分数的模型不存在拦截);
    - 分数 >= model_score_reject_threshold -> R007 reject;
      >= model_score_review_threshold -> R007 review(阈值在 policy 版本表,
      与规则阈值同级治理:默认 0.9/0.98 是"关着"的,生效要审批调低)。
    阈值口径与规则一致:use_current_policy=True 用当前,否则按事件 ts 回放
    当时版本 —— 否则回放历史事件时规则用历史阈值、模型用当前阈值,口径劈叉。
    命中后按 action 权重与既有规则取最重。rule_count_evaluated 相应 +1
    (R007 是引擎级规则,不属 R001-R006 的静态规则集)。"""
    ch = _champion()
    if not ch:
        return result
    result["model_version"] = "%s %s" % (ch["name"], ch["version"])
    uid = event.get("uid", "")
    score = (_model_score_remote(uid, event)
             if os.environ.get(MODEL_URL_ENV) else _model_score_local(uid))
    if score is None:
        result["model_signal"] = "champion 已上线但无模型分数(未接入模型服务/无本地分数)"
        return result
    result["model_score"] = score
    from .tools.policy import active_policy
    from .tools.rules import ACTION_ORDER, _hit
    p = active_policy(None if use_current_policy else event.get("ts"))
    if score >= p["model_score_reject_threshold"]:
        hit_action = "reject"
    elif score >= p["model_score_review_threshold"]:
        hit_action = "review"
    else:
        result["model_signal"] = "champion 风险分 %.3f 低于模型阈值,未命中" % score
        return result
    hits = result.setdefault("hits", [])
    _hit(hits, "R007", "champion 模型 %s 风险分 %.3f 达到 %s 阈值 %.2f"
         % (result["model_version"], score, hit_action, p[
            "model_score_reject_threshold" if hit_action == "reject"
            else "model_score_review_threshold"]), hit_action)
    if ACTION_ORDER[hit_action] > ACTION_ORDER[result.get("action", "pass")]:
        result["action"] = hit_action
    result["rule_count_evaluated"] = (result.get("rule_count_evaluated") or 0) + 1
    result["model_signal"] = "R007 命中(模型分 %.3f)" % score
    return result


def _local_eval(event: Dict[str, Any], use_current_policy: bool,
                strategy: Dict) -> Dict:
    """本地判定 + active strategy 覆盖 + 模型信号,一次打包。"""
    from .tools.rules import _local_rule_eval  # 惰性:防导入环
    r = _local_rule_eval(event, use_current_policy=use_current_policy,
                         threshold_overrides=strategy.get("strategy_thresholds"))
    if strategy:
        r["strategy_version"] = strategy["strategy_version"]
        r["strategy_thresholds"] = strategy["strategy_thresholds"]
        if strategy.get("strategy_ambiguity"):
            r["strategy_ambiguity"] = strategy["strategy_ambiguity"]
    return _apply_model_signal(r, event, use_current_policy=use_current_policy)


def evaluate_event(event: Dict[str, Any],
                   use_current_policy: bool = False) -> Dict[str, Any]:
    """判定的唯一入口。返回结构与本地 rule_eval 兼容,附 source 字段
    (local_rules / remote_engine / local_rules_fallback)供溯源;
    P0-2/P0-3 起,本地判定自动携带 active strategy 覆盖与 champion
    模型信号(R007,见 _apply_model_signal)。"""
    from .tools.rules import _local_rule_eval  # 惰性:防导入环

    strategy = _active_strategy()
    if _overridden():
        r = _local_eval(event, use_current_policy, strategy)
        r["source"] = "local_rules"
        r["source_note"] = ("what-if 覆盖生效,强制本地模拟"
                            "(覆盖参数是本地模拟概念,生产 dry-run 不接收)")
        return r
    url = os.environ.get(DRYRUN_URL_ENV)
    if not url:
        r = _local_eval(event, use_current_policy, strategy)
        r["source"] = "local_rules"
        return r
    try:
        payload = {
            "event": event,
            "use_current_policy": bool(use_current_policy),
        }
        if strategy:
            payload["strategy_version"] = strategy["strategy_version"]
        r = _map_remote(_post_json(url, payload))
        if strategy and not r.get("strategy_version"):
            r["strategy_version"] = strategy["strategy_version"]
        if strategy and strategy.get("strategy_ambiguity"):
            r["strategy_ambiguity"] = strategy["strategy_ambiguity"]
        # 远程模式:模型融合由生产引擎负责,本地只附 champion 血缘
        ch = _champion()
        if ch:
            r["model_version"] = "%s %s" % (ch["name"], ch["version"])
        return r
    except Exception as e:  # noqa: BLE001
        # 显式降级:结果必须带 degraded/engine_error,让结论可被审计到
        r = _local_eval(event, use_current_policy, strategy)
        r["source"] = "local_rules_fallback"
        r["degraded"] = True
        r["engine_error"] = "%s: %s" % (type(e).__name__, e)
        return r


def evaluate_batch(events: List[Dict[str, Any]],
                   use_current_policy: bool = False) -> List[Dict[str, Any]]:
    """批量判定:全量工具(backtest/scan 的 account_verdicts)在远程模式下
    的唯一形态 —— 一次 POST 覆盖全部事件,顺序与请求对齐。覆盖生效/未配置
    引擎时逐条走本地;远程失败逐条显式降级(degraded,不静默)。
    本地逐条同样携带 active strategy 覆盖与 champion 模型信号。"""
    if not events:
        return []
    strategy = _active_strategy()
    if _overridden() or not os.environ.get(DRYRUN_URL_ENV):
        out = []
        for ev in events:
            r = _local_eval(ev, use_current_policy, strategy)
            r["source"] = "local_rules"
            out.append(r)
        return out
    try:
        payload = {
            "events": events,
            "use_current_policy": bool(use_current_policy),
        }
        if strategy:
            payload["strategy_version"] = strategy["strategy_version"]
        raw = _post_json(os.environ[DRYRUN_URL_ENV], payload)
        decisions = raw.get("decisions")
        if not isinstance(decisions, list) or len(decisions) != len(events):
            raise ValueError("批量 dry-run 返回与请求不齐(期望 %d 条,得 %r)"
                             % (len(events), type(decisions).__name__))
        out = [_map_remote(d) for d in decisions]
        if strategy:
            for r in out:
                if not r.get("strategy_version"):
                    r["strategy_version"] = strategy["strategy_version"]
        return out
    except Exception as e:  # noqa: BLE001
        out = []
        for ev in events:
            r = _local_eval(ev, use_current_policy, strategy)
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
