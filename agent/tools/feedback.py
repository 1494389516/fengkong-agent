# -*- coding: utf-8 -*-
"""误伤申诉与复盘回路:被处置用户喊冤 → 核查 → 决议 → 教训沉淀。

这是标签回路的另一半:reports(举报)提供 fraud 方向的标签线索,申诉
提供 normal 方向的 —— 申诉核实成立 = 一次人工审核结论 = 误伤实锤,
应当同时修正标签、解除 uid 名单,并把教训写进复盘日志(postmortems.jsonl),
供研究员转成 eval 误伤守卫用例:线上教训变回归测试,规则改坏了立刻知道。

权限边界与 actions.py 同构:agent 只有"建议 + 提交"权,appeal_resolve 把
决议写进待审批队列(kind=appeal_resolve),研究员 /approve 后才落盘生效。
申诉人的一面之词永远只是线索:决议依据必须来自工具证据(判定/信号/名单/
举报/标签),accept 尤其要写清为什么现有证据不足以支撑原处置。
"""
import json
from typing import Dict, List

from . import tool
from .backtest import account_verdicts
from .blacklist import active_records
from .datasource import (appeals_path, blacklist_path, labels_path, load_accounts,
                         load_appeals, load_blacklist, load_events, load_labels,
                         postmortems_path)
from .reports import report_query

VALID_DECISIONS = ("accept", "reject")  # accept=误伤成立解除处置, reject=维持原判


def _recent_postmortems(limit: int = 3) -> List[Dict]:
    """最近的复盘记录(轻量读侧):处理新申诉前先看同类规则有没有误伤前科。
    转成 eval 误伤守卫用例用 eval/postmortem_to_cases.py。"""
    p = postmortems_path()
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8").splitlines()[-limit:]:
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        out.append({"uid": rec.get("uid"), "kind": rec.get("kind"),
                    "rules_involved": rec.get("rules_involved", [])})
    return out


@tool(
    name="appeal_review",
    description=(
        "误伤申诉队列:列出待处理申诉,逐条联查当前判定/命中规则/标签/LTV/"
        "uid 名单/属实举报,并给出建议(uphold 维持 / release 解除 / investigate "
        "需深查)。申诉核实成立 = 误伤实锤,是标签回路 normal 方向的来源。"
        "点名提交待审批才用 appeal_resolve;用户要求立即生效/不用审批时"
        "不要调 appeal_resolve,只复核并说明须 /approve。"
    ),
    parameters={"type": "object", "properties": {}},
)
def appeal_review():
    appeals = load_appeals()
    pending = [a for a in appeals if a.get("status") == "pending"]
    if not pending:
        return {"pending_count": 0, "total": len(appeals),
                "recent_postmortems": _recent_postmortems(),
                "note": "无待处理申诉" if appeals else "无申诉记录(appeals.json 缺失或为空)"}
    events = load_events()
    labels = load_labels()
    accounts = load_accounts()
    verdicts = account_verdicts([a["uid"] for a in pending], events)
    out = []
    for a in pending:
        uid = a["uid"]
        v = verdicts.get(uid, {})
        label = (labels.get(uid) or {}).get("label")
        ltv = (accounts.get(uid) or {}).get("ltv")
        # 只看未过期记录:过期名单在规则引擎里"视为不存在",拿失效证据
        # 建议维持(或阻断解除)会让申诉结论与实际判定口径脱节
        bl = active_records("uid", uid)
        verified = report_query(uid)["verified_count"]
        # 建议只看硬证据,申诉文案不参与:fraud 标签/属实举报/黑名单任一在手
        # 即建议维持;干干净净(normal 或无标签 + 无处置 + 无不利名单)建议解除
        # —— 白名单是既往误伤的免责凭证,不是嫌疑记录,不阻断"干净"判定;
        # 其余(有处置但证据链存疑)交人工深查 —— 建议永远只是排序,不是决议
        strong = label == "fraud" or verified > 0 or any(r["list"] == "black" for r in bl)
        adverse = [r for r in bl if r["list"] != "white"]
        clean = (label in (None, "normal") and v.get("predicted", "pass") == "pass"
                 and not adverse and verified == 0)
        rec = "uphold" if strong else ("release" if clean else "investigate")
        out.append({
            "appeal_id": a["appeal_id"], "uid": uid, "claim": a["claim"],
            "current_verdict": v.get("predicted"), "rules": v.get("rules", []),
            "label": label, "ltv": ltv,
            "uid_blacklist": [r["list"] for r in bl],
            "verified_reports": verified,
            "recommendation": rec,
        })
    return {
        "pending_count": len(out),
        "queue": out,
        "recent_postmortems": _recent_postmortems(),
        "note": "recommendation 只是排序建议;点名提交待审批才用 appeal_resolve;"
                "用户要求立即生效时不要提交,只说明须 /approve;"
                "accept 需说明为何现有证据不足以支撑原处置",
    }


@tool(
    name="appeal_resolve",
    description=(
        "提交申诉决议(不会立即生效,须 /approve):decision=accept(误伤成立)"
        "或 reject(维持原判),进待审批队列。用户要求立即生效/不用审批时"
        "不要调用,只 appeal_review 并说明须人工 /approve。"
        "accept 批准后:申诉 accepted、解除该 uid 名单、标签改 normal、写复盘。"
        "reason 须引用工具证据。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "appeal_id": {"type": "integer"},
            "decision": {"type": "string", "enum": list(VALID_DECISIONS)},
            "reason": {"type": "string",
                       "description": "决议依据(判定/信号/名单/举报证据),进入审计日志"},
        },
        "required": ["appeal_id", "decision", "reason"],
    },
)
def appeal_resolve(appeal_id: int, decision: str, reason: str):
    if decision not in VALID_DECISIONS:
        return {"error": "decision 必须是 %s 之一" % (VALID_DECISIONS,)}
    matched = [a for a in load_appeals() if a["appeal_id"] == appeal_id]
    if not matched:
        return {"error": "查无申诉 appeal_id=%d" % appeal_id}
    if matched[0].get("status") != "pending":
        return {"status": "already_resolved", "appeal": matched[0]}
    from .actions import _load_pending, _now_iso, _save_pending
    pending = _load_pending()
    dup = [p for p in pending if p.get("kind") == "appeal_resolve"
           and p.get("appeal_id") == appeal_id]
    if dup:
        return {"status": "already_pending", "action_id": dup[0]["action_id"]}
    action_id = max((p["action_id"] for p in pending), default=0) + 1
    uid = matched[0]["uid"]
    rules_now = account_verdicts([uid], load_events())[uid]["rules"]
    pending.append({
        "action_id": action_id,
        "kind": "appeal_resolve",
        "appeal_id": appeal_id,
        "uid": uid,
        "decision": decision,
        "rules_at_resolution": rules_now,
        "reason": reason,
        "requested_at": _now_iso(),
    })
    _save_pending(pending)
    return {"status": "pending_confirmation", "action_id": action_id,
            "note": "已提交待审批,需研究员在 CLI 执行 /approve %d 后生效" % action_id}


def apply_appeal_decision(action: Dict) -> Dict:
    """actions.decide 批准 appeal_resolve 后调用:落盘申诉状态;accept 额外
    解除 uid 名单、修正标签、写复盘日志。返回落盘摘要(进审计日志)。"""
    appeal_id, uid, decision = action["appeal_id"], action["uid"], action["decision"]
    # 逐条拷贝再改:load_appeals 返回的是进程内缓存,就地改 status 后若写盘
    # 失败(文件 mtime 未变、缓存不失效),缓存里会留下一个从未落盘的幻影状态
    appeals = [dict(a) for a in load_appeals()]
    for a in appeals:
        if a["appeal_id"] == appeal_id:
            a["status"] = "accepted" if decision == "accept" else "rejected"
    from .datasource import append_jsonl, atomic_write_json
    atomic_write_json(appeals_path(), appeals)
    applied = {"appeal_status": "accepted" if decision == "accept" else "rejected"}
    if decision == "accept":
        # ① 解除 uid 维度的黑/灰记录(ip/设备维度不动:资源可能仍被他人滥用;
        #    白名单更不能动 —— 那是误伤保护,删掉等于让刚洗清的用户裸奔)
        records = load_blacklist()
        kept = [r for r in records if not (r["dimension"] == "uid" and r["value"] == uid
                                           and r["list"] != "white")]
        if len(kept) != len(records):
            atomic_write_json(blacklist_path(), kept)
            applied["blacklist_removed"] = len(records) - len(kept)
        # ② 标签修正:申诉核实 = 人工审核结论,这就是标签回填的正规渠道
        raw = json.loads(labels_path().read_text(encoding="utf-8")) \
            if labels_path().exists() else {}
        old_label = (raw.get(uid) or {}).get("label")
        raw[uid] = {"label": "normal",
                    "note": "申诉 #%d 核实误伤: %s" % (appeal_id, action["reason"][:80])}
        atomic_write_json(labels_path(), raw)
        applied["label_set"] = "normal"
        from .label_lifecycle import write_label_lineage  # 标签修正血缘
        write_label_lineage(uid, old_label, "normal", source="appeal",
                            appeal_id=appeal_id)
        # ③ 复盘沉淀:教训写进 jsonl,研究员定期转 eval 误伤守卫用例
        append_jsonl(postmortems_path(), {
            "ts": action.get("requested_at"),
            "kind": "false_positive_appeal",
            "uid": uid,
            "appeal_id": appeal_id,
            "rules_involved": action.get("rules_at_resolution", []),
            "reason": action["reason"],
            "followup": "建议将该账号行为模式补进 eval 误伤守卫用例",
        })
        applied["postmortem_logged"] = True
    return applied
