# -*- coding: utf-8 -*-
"""规则回测工具:对全量标注账号跑规则集,输出混淆矩阵与 precision/recall/F1。

设计约定:指标计算是确定性代码,不让模型心算 —— 模型只负责解读结果、
提出调参假设,再用 overrides 做 what-if 验证(临时生效、不落盘),
形成"改阈值 → 看指标"的闭环。

口径:标签标在账号上,账号任一事件被规则标记,即视为该账号被标记。
两个 operating point 一起报:
  flag=review+reject —— 宽口径,review 也算拦下(有人工兜底)
  flag=reject_only   —— 严口径,只算硬拦截
两者的差值就是"人工审核队列在扛多少召回",是评估 gray→review 这类
柔性处置价值的直接证据。
"""
from typing import Dict, Iterable, List, Optional

from . import tool
from . import policy
from . import rules
from .datasource import load_accounts, load_events, load_labels
from .rules import rule_eval

# 误伤流失系数:被误拦的正常账号流失概率的保守估计。只用于期望损失的
# 排序比较(哪个阈值更亏),不是财务口径 —— 真实流失率应由业务侧回填。
CHURN_RISK = 0.2

# 可被 what-if 覆盖的阈值键(规则组;monitor 组不在列,回测不跑监控)。
# 覆盖经 policy.set_overrides 生效:先全量校验后原子应用,finally 恢复旧快照。
OVERRIDABLE = policy.RULE_KEYS

# 标签口径(借鉴 MARS 的 target 规则):有效值只有这两个,其他值直接报错
# 而不是静默当 normal —— "Fraud"/"suspect"/1 混进来会无声污染混淆矩阵,
# 让指标看起来还行但完全不可信。清洗是标注方的责任,不在指标里兜底。
VALID_LABELS = ("fraud", "normal")


def label_observation(labels: Dict[str, Dict], events: List[Dict]) -> Dict:
    """标签表现覆盖:数据集里多少账号已标注(已表现)、多少尚未标注。
    借鉴 MARS 的 target_observation:P/R/F1 只算已标注账号,未标注不是
    "正常",是"还不知道" —— 覆盖率低时指标只代表已表现子集,有选择偏差
    (先被人工审的往往就是可疑的),解读回测结果必须连它一起看。"""
    all_uids = {e["uid"] for e in events}
    labeled = all_uids & set(labels)
    fraud = sum(1 for u in labeled if labels[u]["label"] == "fraud")
    return {
        "accounts_total": len(all_uids),
        "labeled": len(labeled),
        "unlabeled": len(all_uids) - len(labeled),
        "coverage": round(len(labeled) / len(all_uids), 4) if all_uids else None,
        "observed_fraud_rate": round(fraud / len(labeled), 4) if labeled else None,
        "note": "指标只反映已标注账号;未标注=尚未表现,不代表正常",
    }


# 判定缓存:daily_brief 一次调用会经 scan/rule_drift 把全量规则回放跑好几遍,
# 真实数据量下不可接受。key 覆盖判定的全部输入面:数据文件 mtime(事件/名单/
# 主档/策略/设备与 IP 情报)+ what-if 覆盖 + 事件切片指纹 + 账号集。任何
# 输入变化(含审批生效、申诉解名单)都会改 mtime 使缓存自然失效。
_VERDICT_CACHE: Dict[tuple, Dict[str, Dict]] = {}
_VERDICT_CACHE_MAX = 64


def _dataset_fingerprint() -> tuple:
    from .datasource import data_dir
    d = data_dir()
    parts = []
    for f in ("events_sample.json", "blacklist.json", "accounts.json",
              "thresholds.json", "device_intel.json", "ip_intel.json"):
        try:
            parts.append((d / f).stat().st_mtime_ns)
        except OSError:
            parts.append(None)
    return (str(d), tuple(parts))


def account_verdicts(uids: Iterable[str], events: List[Dict]) -> Dict[str, Dict]:
    """逐账号跑规则集:账号内任一事件命中即记入,处置取最重。
    scan_all(全量巡检)与 backtest(指标回测)共用这一份口径。"""
    uids = sorted(uids)
    cache_key = (_dataset_fingerprint(), policy.overrides_key(),
                 len(events), events[0]["ts"] if events else None,
                 events[-1]["ts"] if events else None, tuple(uids))
    hit = _VERDICT_CACHE.get(cache_key)
    if hit is not None:
        return hit
    verdicts = {}
    for uid in uids:
        worst = "pass"
        hit_rules: set = set()
        reasons: List[str] = []
        for e in (e for e in events if e["uid"] == uid):
            # 用当前策略评估历史数据(评估口径);逐事件回放当时策略是审计口径,
            # 那个走 rule_eval 默认行为
            r = rule_eval(e, use_current_policy=True)
            if rules.ACTION_ORDER[r["action"]] > rules.ACTION_ORDER[worst]:
                worst = r["action"]
            for h in r["hits"]:
                if h["rule_id"] not in hit_rules:
                    reasons.append("%s: %s" % (h["rule_id"], h["reason"]))
                hit_rules.add(h["rule_id"])
        verdicts[uid] = {"predicted": worst, "rules": sorted(hit_rules), "reasons": reasons[:3]}
    if len(_VERDICT_CACHE) >= _VERDICT_CACHE_MAX:
        _VERDICT_CACHE.pop(next(iter(_VERDICT_CACHE)))
    _VERDICT_CACHE[cache_key] = verdicts
    return verdicts


def _prf(tp: int, fp: int, fn: int) -> Dict[str, float]:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f1, 4)}


def backtest(overrides: Optional[Dict] = None):
    """核心逻辑,同时供工具调用、chart_threshold_sweep、shadow_compare 与离线 eval 复用。

    覆盖必须整体校验后才应用(原子):部分应用会把错误值泄漏给进程内
    后续所有调用。finally 恢复旧快照而非清空,嵌套/连续调用互不污染。"""
    overrides = overrides or {}
    bad = [k for k in overrides if k not in OVERRIDABLE]
    if bad:
        return {"error": "不支持的阈值参数: %s(可用: %s)" % (", ".join(bad), ", ".join(OVERRIDABLE))}
    applied = dict(overrides)
    prev = policy.set_overrides(overrides)
    try:
        labels = load_labels()
        bad_labels = sorted(u for u, v in labels.items()
                            if v.get("label") not in VALID_LABELS)
        if bad_labels:
            return {"error": "标签只允许 %s,以下账号标签非法(先清洗再回测): %s" % (
                "/".join(VALID_LABELS), ", ".join(bad_labels[:10]))}
        events = load_events()
        verdicts = account_verdicts(labels.keys(), events)
        per_account = {
            uid: {"label": labels[uid]["label"], "predicted": v["predicted"], "rules": v["rules"]}
            for uid, v in verdicts.items()
        }

        # 成本素材:账号订单总额(欺诈账号的止损/漏放口径)与 LTV(误伤面临
        # 流失的价值上限)。无主档时 LTV 记 0 并在 cost 注明 —— 宁可低估误伤
        # 代价也不编数。
        accounts_meta = load_accounts()
        order_sum: Dict[str, float] = {}
        for e in events:
            if e["type"] == "order" and e.get("amount") is not None:
                order_sum[e["uid"]] = order_sum.get(e["uid"], 0.0) + e["amount"]

        points = {}
        for point, flagged_actions in (("flag=review+reject", ("review", "reject")),
                                       ("flag=reject_only", ("reject",))):
            tp = fp = fn = tn = 0
            blocked_amt = missed_amt = fp_ltv = 0.0
            for uid, a in per_account.items():
                flagged = a["predicted"] in flagged_actions
                fraud = a["label"] == "fraud"
                if flagged and fraud:
                    tp += 1
                    blocked_amt += order_sum.get(uid, 0.0)
                elif flagged:
                    fp += 1
                    fp_ltv += (accounts_meta.get(uid) or {}).get("ltv", 0.0)
                elif fraud:
                    fn += 1
                    missed_amt += order_sum.get(uid, 0.0)
                else:
                    tn += 1
            points[point] = {
                "tp": tp, "fp": fp, "fn": fn, "tn": tn, **_prf(tp, fp, fn),
                # 期望损失 = 漏放的欺诈金额 + 流失系数 × 误伤账号 LTV。
                # 只用于同数据集上不同阈值的排序比较,不是财务报表口径。
                "cost": {
                    "blocked_fraud_amount": round(blocked_amt, 2),
                    "missed_fraud_amount": round(missed_amt, 2),
                    "fp_ltv_at_risk": round(fp_ltv, 2),
                    "expected_loss": round(missed_amt + CHURN_RISK * fp_ltv, 2),
                    **({} if accounts_meta else {"note": "无账号主档,LTV 按 0 计"}),
                },
            }

        # 规则贡献:逐规则 TP/FP、独有召回(只有它抓到的欺诈账号)与两两重叠。
        # 删规则和加规则一样需要证据:unique_tp=0 的规则是精简候选,但要先看
        # 它和谁重叠 —— 冗余可能是有意的纵深(名单挂了,行为规则还能兜住)。
        hits_by_rule: Dict[str, set] = {}
        for uid, a in per_account.items():
            for rid in a["rules"]:
                hits_by_rule.setdefault(rid, set()).add(uid)
        rule_contribution = {}
        for rid, uids in sorted(hits_by_rule.items()):
            tp_uids = {u for u in uids if per_account[u]["label"] == "fraud"}
            unique_tp = {u for u in tp_uids
                         if all(rid2 == rid or u not in hits_by_rule[rid2]
                                for rid2 in hits_by_rule)}
            rule_contribution[rid] = {
                "hits": len(uids),
                "tp": len(tp_uids),
                "fp": len(uids) - len(tp_uids),
                "unique_tp": len(unique_tp),
                # 重叠明细只在疑似冗余(无独有召回)时给:那是"能不能删"的
                # 判断现场;有独有召回的规则本就该留,明细纯占 token
                **({"overlap": {r2: len(uids & u2)
                                for r2, u2 in sorted(hits_by_rule.items())
                                if r2 != rid and uids & u2}}
                   if not unique_tp else {}),
            }

        misclassified = [
            {"uid": uid, "label": a["label"], "predicted": a["predicted"], "rules": a["rules"]}
            for uid, a in per_account.items()
            if (a["label"] == "fraud") != (a["predicted"] != "pass")
        ]
        return {
            "accounts_evaluated": len(per_account),
            "label_observation": label_observation(labels, events),
            "overrides_applied": applied,
            "operating_points": points,
            "rule_contribution": rule_contribution,
            "per_account": per_account,
            "misclassified_at_review_point": misclassified,
        }
    finally:
        policy.restore_overrides(prev)


def shadow_compare(overrides: Dict):
    """影子对比:当前策略 vs 候选阈值,对同一批标注账号各跑一次回测。
    切换阈值前的必经步骤 —— 不看差异直接切换,就是拿反馈回路赌运气。"""
    base = backtest()
    cand = backtest(overrides)
    if "error" in cand:
        return cand
    flagged = lambda r, uid: r["per_account"][uid]["predicted"] != "pass"  # noqa: E731
    newly_flagged = sorted(u for u in base["per_account"]
                           if not flagged(base, u) and flagged(cand, u))
    newly_passed = sorted(u for u in base["per_account"]
                          if flagged(base, u) and not flagged(cand, u))
    wb = base["operating_points"]["flag=review+reject"]
    wc = cand["operating_points"]["flag=review+reject"]
    return {
        "overrides": overrides,
        "active": base["operating_points"],
        "candidate": cand["operating_points"],
        "delta": {"wide_%s" % k: round(wc[k] - wb[k], 4)
                  for k in ("precision", "recall", "f1")},
        "newly_flagged": newly_flagged,
        "newly_passed": newly_passed,
        "changed_accounts": len(newly_flagged) + len(newly_passed),
    }


@tool(
    name="shadow_backtest",
    description=(
        "影子回测:当前生效策略 vs 候选阈值,对同一批标注账号的差异对比 —— "
        "双方指标、指标增量、以及哪些账号会'新被拦下'(newly_flagged)/"
        "'新被放过'(newly_passed)。提议或批准任何阈值变更前必须先看这个。"
        "overrides 键同 rule_backtest。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "overrides": {
                "type": "object",
                "description": "候选阈值,如 {\"r002_max_gap_seconds\": 15}",
            },
        },
        "required": ["overrides"],
    },
)
def shadow_backtest(overrides: Dict):
    r = shadow_compare(overrides or {})
    return r if "error" in r else _attach_sim_trust(r)


@tool(
    name="rule_backtest",
    description=(
        "对全量标注账号回测当前生效策略(评估口径:当前阈值 × 历史数据),返回两个"
        "口径(flag=review+reject / flag=reject_only)的混淆矩阵与 P/R/F1、规则贡献、"
        "成本视角、误判清单。overrides 可临时覆盖阈值做 what-if(不修改配置,可用键"
        "见参数说明)。凡涉及规则效果/指标的问题必须用本工具取数,不要自行推算。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "overrides": {
                "type": "object",
                "description": "临时阈值覆盖,可用键:" + ", ".join(OVERRIDABLE),
            },
        },
    },
)
def rule_backtest(overrides: Optional[Dict] = None):
    r = backtest(overrides)
    if "error" in r:
        return r
    # 工具面瘦身:per_account 在真实规模数据上是整包结果的 90%+(逐账号明细
    # 模型也消化不了),只留指标与误判清单;内部调用方(shadow/eval)仍走
    # backtest() 拿全量。
    slim = {k: v for k, v in r.items() if k != "per_account"}
    slim["per_account_note"] = ("逐账号明细未随返回(共 %d 账号,防上下文爆炸);"
                                "查单账号用 account_profile / rule_eval" % r["accounts_evaluated"])
    mis = slim.get("misclassified_at_review_point", [])
    if len(mis) > 10:  # 误判清单同理只给样例,总数在混淆矩阵里
        slim["misclassified_at_review_point"] = mis[:10]
        slim["misclassified_note"] = "误判共 %d 个,仅列前 10;总数见 operating_points" % len(mis)
    return _attach_sim_trust(slim)


def _attach_sim_trust(result: Dict) -> Dict:
    """模拟类结论必须自带对账标记:模拟器失信时指标不可作为变更依据。"""
    from .reconcile import sim_trust
    st = sim_trust()
    if st is not None:
        result["sim_consistency"] = st
    return result
