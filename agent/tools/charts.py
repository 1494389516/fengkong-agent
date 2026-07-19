# -*- coding: utf-8 -*-
"""图表工具:把数据画成自包含 HTML(内联 SVG)落盘到 out/charts/。

设计约定(为什么这样设计):
- 图是给人看的,模型看不了图 —— 返回给模型的只有"文件路径 + 数字摘要",
  序列原文与图形本体绝不进对话上下文(那是 token 爆炸的重灾区)。
- 零依赖:手写 SVG,不引 matplotlib,骨架阶段 pip 依赖保持最少。
"""
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from . import tool
from .backtest import backtest

ROOT = Path(__file__).resolve().parent.parent.parent
OUT = ROOT / "out" / "charts"
DATA = ROOT / "data" / "events_sample.json"

PALETTE = ["#4e79a7", "#f28e2b", "#e15759", "#76b7b2", "#59a14f",
           "#edc948", "#b07aa1", "#ff9da7"]

# chart_threshold_sweep 各参数的默认扫描序列(键必须是 backtest.OVERRIDABLE 的子集)
SWEEP_DEFAULTS = {
    "r002_max_gap_seconds": [5, 15, 30, 60, 120, 240, 300, 600],
    "r002_min_events": [3, 5, 10, 15, 20, 30],
    "r002_reject_min_ips": [2, 3, 4, 5, 6],
    "r003_high_amount": [200, 500, 1000, 2000, 5000, 8000],
    "r003_cashout_max_amount": [5, 10, 20, 50, 100],
    "r003_cashout_min_coupons": [1, 2, 3, 4, 5],
}


def _fmt_ts(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%m-%d %H:%M:%S")


def _write_html(filename: str, title: str, svg: str, note: str = "") -> str:
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / filename
    path.write_text(
        '<!doctype html><meta charset="utf-8"><title>%s</title>'
        '<body style="font-family:sans-serif;margin:24px">'
        "<h3>%s</h3>%s<p style=\"color:#777;font-size:12px\">%s</p>" % (title, title, svg, note),
        encoding="utf-8")
    return str(path.relative_to(ROOT))


@tool(
    name="chart_account_timeline",
    description=(
        "把某 uid 的事件流画成时间线图并写成本地 HTML 文件:按事件类型分道、"
        "按 IP 着色、订单点标金额。返回文件路径与数字摘要。适合排查单账号行为"
        "模式;回答时把路径告诉研究员即可,不要尝试用文字复述图形。"
    ),
    parameters={
        "type": "object",
        "properties": {"uid": {"type": "string", "description": "用户 ID"}},
        "required": ["uid"],
    },
)
def chart_account_timeline(uid: str):
    events = sorted((e for e in json.loads(DATA.read_text(encoding="utf-8")) if e["uid"] == uid),
                    key=lambda e: e["ts"])
    if not events:
        return {"uid": uid, "found": False}
    t0, t1 = events[0]["ts"], events[-1]["ts"]
    span = max(t1 - t0, 1)
    types = sorted({e["type"] for e in events})
    ips = sorted({e["ip"] for e in events})
    color = {ip: PALETTE[i % len(PALETTE)] for i, ip in enumerate(ips)}

    ml, plot_w, mt, lane_h, mb = 110, 480, 30, 46, 45
    w = ml + plot_w + 210
    h = mt + lane_h * len(types) + mb
    p = ['<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" '
         'font-family="sans-serif" font-size="11">' % (w, h)]
    for i, t in enumerate(types):
        y = mt + lane_h * i + lane_h // 2
        p.append('<text x="%d" y="%d" text-anchor="end" fill="#555">%s</text>' % (ml - 10, y + 4, t))
        p.append('<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#eee"/>' % (ml, y, ml + plot_w, y))
    for e in events:
        x = ml + (e["ts"] - t0) / span * plot_w
        y = mt + lane_h * types.index(e["type"]) + lane_h // 2
        p.append('<circle cx="%.1f" cy="%d" r="5" fill="%s" fill-opacity="0.85">'
                 "<title>%s ip=%s</title></circle>" % (x, y, color[e["ip"]], _fmt_ts(e["ts"]), e["ip"]))
        if e.get("amount") is not None:
            p.append('<text x="%.1f" y="%d" text-anchor="middle" fill="#333">%.1f</text>' % (x, y - 10, e["amount"]))
    p.append('<text x="%d" y="%d" fill="#555">%s</text>' % (ml, h - 15, _fmt_ts(t0)))
    p.append('<text x="%d" y="%d" text-anchor="end" fill="#555">%s</text>' % (ml + plot_w, h - 15, _fmt_ts(t1)))
    for i, ip in enumerate(ips):  # 图例:IP -> 颜色
        y = mt + 16 * i
        p.append('<circle cx="%d" cy="%d" r="5" fill="%s"/>' % (ml + plot_w + 25, y, color[ip]))
        p.append('<text x="%d" y="%d" fill="#333">%s</text>' % (ml + plot_w + 35, y + 4, ip))
    p.append("</svg>")

    path = _write_html("timeline_%s.html" % uid, "账号 %s 事件时间线" % uid, "".join(p),
                       "圆点按 IP 着色;订单点上方标金额;悬停看时间与 IP。")
    return {
        "uid": uid,
        "found": True,
        "chart_path": path,
        "summary": {
            "event_count": len(events),
            "span_seconds": t1 - t0,
            "distinct_ip": len(ips),
            "distinct_device": len({e["device_id"] for e in events}),
            "types": types,
        },
    }


@tool(
    name="chart_threshold_sweep",
    description=(
        "对单个规则阈值做扫描回测:逐个候选值跑 rule_backtest,画出 precision/"
        "recall/F1 随阈值变化的曲线(本地 HTML),返回文件路径、逐点指标表与 F1 "
        "最优值。规则调参前先用它看指标对该参数的敏感度。param 可选:"
        + ", ".join(SWEEP_DEFAULTS)
    ),
    parameters={
        "type": "object",
        "properties": {
            "param": {"type": "string", "enum": list(SWEEP_DEFAULTS), "description": "要扫描的阈值参数"},
            "values": {"type": "array", "items": {"type": "number"},
                       "description": "自定义扫描值,缺省用内置序列"},
        },
        "required": ["param"],
    },
)
def chart_threshold_sweep(param: str, values: Optional[List[float]] = None):
    values = values or SWEEP_DEFAULTS[param]
    rows = []
    for v in values:
        r = backtest({param: v})
        m = r["operating_points"]["flag=review+reject"]
        rows.append({"value": v, "precision": m["precision"], "recall": m["recall"], "f1": m["f1"]})

    ml, plot_w, mt, plot_h = 60, 520, 30, 260
    w, h = ml + plot_w + 130, mt + plot_h + 60
    xs = [ml + i / max(len(values) - 1, 1) * plot_w for i in range(len(values))]

    def y_of(v):
        return mt + (1 - v) * plot_h

    p = ['<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" '
         'font-family="sans-serif" font-size="11">' % (w, h)]
    for g in (0.0, 0.25, 0.5, 0.75, 1.0):  # 横向网格 + y 刻度
        y = y_of(g)
        p.append('<line x1="%d" y1="%.1f" x2="%d" y2="%.1f" stroke="#eee"/>' % (ml, y, ml + plot_w, y))
        p.append('<text x="%d" y="%.1f" text-anchor="end" fill="#555">%.2f</text>' % (ml - 8, y + 4, g))
    for x, v in zip(xs, values):  # x 刻度:候选值等距摆放(类目轴,避免宽量程挤成一团)
        p.append('<text x="%.1f" y="%d" text-anchor="middle" fill="#555">%g</text>' % (x, mt + plot_h + 18, v))
    for i, metric in enumerate(("precision", "recall", "f1")):
        c = PALETTE[i]
        pts = " ".join("%.1f,%.1f" % (x, y_of(row[metric])) for x, row in zip(xs, rows))
        p.append('<polyline points="%s" fill="none" stroke="%s" stroke-width="2"/>' % (pts, c))
        for x, row in zip(xs, rows):
            p.append('<circle cx="%.1f" cy="%.1f" r="3" fill="%s"/>' % (x, y_of(row[metric]), c))
        ly = mt + 18 * i
        p.append('<rect x="%d" y="%d" width="12" height="3" fill="%s"/>' % (ml + plot_w + 20, ly, c))
        p.append('<text x="%d" y="%d" fill="#333">%s</text>' % (ml + plot_w + 38, ly + 6, metric))
    p.append('<text x="%d" y="%d" text-anchor="middle" fill="#555">%s</text>' % (ml + plot_w // 2, h - 8, param))
    p.append("</svg>")

    best = max(rows, key=lambda r: r["f1"])
    path = _write_html("sweep_%s.html" % param, "阈值扫描:%s" % param, "".join(p),
                       "口径 flag=review+reject;当前配置值见 agent/tools/rules.py。")
    return {"param": param, "chart_path": path, "rows": rows,
            "best_by_f1": {"value": best["value"], "f1": best["f1"]}}
