# -*- coding: utf-8 -*-
"""账号调查档案工具:一次调用拿齐调查一个账号需要的全部维度。

维度构成(为什么是这几块):
- 注册上下文:账号的"出生证明" —— 事后行为可以伪装,出生环境洗不掉;
  注册 IP/设备联查名单,批量注册/渠道包一眼可见。
- 账龄错配:注册->首单间隔。新号做老号的事(R004 的档案版视角)。
- 价值与误伤代价:LTV 分档。风控原则是"拦截收益 vs 误伤代价",高价值
  老客与零消费新号命中同一规则,处置建议应完全不同 —— 这里把原则变成字段。
- 当前判定 / 监控信号 / 关联分量:现有工具的汇总视图。
- 处置历史:audit.jsonl 里该 uid 的名单审批记录("前科"与误伤申诉的雏形;
  目前只查 uid 维度的名单条目,ip/设备维度的关联处置暂不归并)。
"""
import json
from typing import Dict, List, Optional

from . import tool
from .backtest import account_verdicts
from .blacklist import blacklist_query
from .datasource import audit_log_path, load_accounts, load_events, load_reports
from .features import feature_stats
from .graph import component_summary
from .intel import ip_type_summary
from .monitor import account_monitor

# LTV 分档:误伤代价的粗颗粒度量。档位只影响"处置建议措辞",不改判定 ——
# 判定归规则,代价归人权衡,两者在输出里分开呈现。
LTV_HIGH = 1000.0
LTV_MEDIUM = 100.0


def _value_tier(ltv: float) -> Dict:
    if ltv >= LTV_HIGH:
        return {"ltv": ltv, "tier": "high",
                "note": "高价值账号:误伤代价高,reject 需要强证据,优先 review + 人工联系"}
    if ltv >= LTV_MEDIUM:
        return {"ltv": ltv, "tier": "medium",
                "note": "有消费历史:处置前核对自身基线偏离,避免误伤存量用户"}
    return {"ltv": ltv, "tier": "low",
            "note": "低/零价值账号:误伤代价低,可按规则从严处置"}


def _disposal_history(uid: str) -> List[Dict]:
    path = audit_log_path()
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        a = rec.get("action", {})
        if (a.get("kind", "blacklist_add") == "blacklist_add"
                and a.get("dimension") == "uid" and a.get("value") == uid):
            out.append({"ts": rec.get("ts"), "decision": rec.get("decision"),
                        "list": a.get("list"), "reason": a.get("reason")})
    return out


@tool(
    name="account_profile",
    description=(
        "账号一站式调查档案:注册主档(时间/方式/渠道/注册 IP 与设备的名单联查)、"
        "账龄与注册->首单间隔(账龄错配)、价值分档(LTV,给出误伤代价提示)、"
        "当前策略下的判定与命中规则、监控信号(含自身基线与地理跳变)、"
        "IP 类型分布(家宽/基站/机房/代理)、关联分量(团伙)、被举报摘要、"
        "该 uid 的历史处置审批记录。调查'这个账号什么情况'类问题先调这个,"
        "再按需用单项工具深挖。"
    ),
    parameters={
        "type": "object",
        "properties": {"uid": {"type": "string", "description": "用户 ID"}},
        "required": ["uid"],
    },
)
def account_profile(uid: str):
    events = load_events()
    mine = sorted((e for e in events if e["uid"] == uid), key=lambda e: e["ts"])
    acct: Optional[Dict] = load_accounts().get(uid)
    result: Dict = {"uid": uid, "found_account": acct is not None,
                    "found_events": bool(mine)}

    if acct:
        # 数据集时钟:离线数据没有"现在",用全数据集最新事件时间当参照
        clock = max((e["ts"] for e in events), default=acct["registered_at"])
        age_days = round((clock - acct["registered_at"]) / 86400, 1)
        reg_flags = []
        for dim, val in (("ip", acct.get("register_ip")), ("device_id", acct.get("register_device"))):
            if val:
                for rec in blacklist_query(dim, val)["records"]:
                    reg_flags.append("注册%s=%s 命中%s名单: %s" % (dim, val, rec["list"], rec["reason"]))
        first_order = next((e for e in mine if e["type"] == "order"), None)
        result["account"] = acct
        result["age_days"] = age_days
        result["registration_flags"] = reg_flags
        result["first_order_gap_seconds"] = (
            first_order["ts"] - acct["registered_at"] if first_order else None)
        # 案发设备 vs 注册设备:老号突然全换环境是盗用信号(自身基线的档案版)
        if mine and acct.get("register_device"):
            used_devices = {e["device_id"] for e in mine}
            if acct["register_device"] not in used_devices:
                result["registration_flags"] = reg_flags + [
                    "近期事件全部来自非注册设备(注册 %s,近期 %s)" % (
                        acct["register_device"], "、".join(sorted(used_devices)))]
        result["value"] = _value_tier(acct.get("ltv", 0.0))

    if mine:
        result["current_verdict"] = account_verdicts([uid], events)[uid]
        feats = feature_stats(uid)
        result["features"] = feats
        result["behavior_paths"] = feats.get("behavior")  # 序列签名,档案顶层直读
        # IP 质量:distinct_ip 是数量,这里是物种(家宽/基站/机房/代理)
        result["ip_types"] = ip_type_summary({e["ip"] for e in mine})
        mon = account_monitor(uid)
        result["monitor"] = {k: mon[k] for k in
                             ("signal_types", "anomalous_windows", "shared_devices",
                              "blacklist_signals", "self_baseline_signals", "geo_jumps",
                              "risky_devices")}
        result["relations"] = component_summary(uid)

    # 举报摘要:verified 是强证据;dismissed 是"曾被误举报"的澄清证据,不作处置依据
    against = [r for r in load_reports() if r.get("reported_uid") == uid]
    result["reports_against"] = {
        "count": len(against),
        "verified": sum(1 for r in against if r.get("status") == "verified"),
        "categories": sorted({r.get("category") for r in against}),
    } if against else {"count": 0}

    result["disposal_history"] = _disposal_history(uid)
    return result
