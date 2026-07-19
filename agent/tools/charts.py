# -*- coding: utf-8 -*-
"""图表工具:matplotlib + pandas 渲染 PNG,落盘到 out/charts/。

设计约定(为什么这样设计):
- 图是给人看的,模型看不了图 —— 返回给模型的只有"文件路径 + 数字摘要",
  序列原文与图形本体绝不进对话上下文(那是 token 爆炸的重灾区)。
- 无头环境用 Agg 后端(必须在 pyplot 导入前设置)。
- 中文标题依赖 CJK 字体,启动时探测,探测不到回退英文标题 ——
  图内数据文本(uid/ip/事件类型/指标名)本来就是 ASCII,不受影响。
"""
import json
from pathlib import Path
from typing import List, Optional

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

from . import tool  # noqa: E402
from .backtest import backtest  # noqa: E402
from .monitor import MONITOR_BURST_MIN  # noqa: E402

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


def _setup_cjk() -> bool:
    import logging
    from matplotlib import font_manager
    # WenQuanYi 等 CJK 字体只有 500 字重,matplotlib 每次 findfont 都会告警;
    # 回退行为本身正确,压掉这条噪音日志。
    logging.getLogger("matplotlib.font_manager").setLevel(logging.ERROR)
    names = {f.name for f in font_manager.fontManager.ttflist}
    for cand in ("Noto Sans CJK SC", "WenQuanYi Zen Hei", "WenQuanYi Micro Hei",
                 "PingFang SC", "Microsoft YaHei", "SimHei"):
        if cand in names:
            plt.rcParams["font.sans-serif"] = [cand] + plt.rcParams["font.sans-serif"]
            plt.rcParams["axes.unicode_minus"] = False
            return True
    return False


_HAS_CJK = _setup_cjk()


def _t(zh: str, en: str) -> str:
    """标题文案:有 CJK 字体用中文,否则英文,避免渲染成方块。"""
    return zh if _HAS_CJK else en


def _save(fig, filename: str) -> str:
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / filename
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return str(path.relative_to(ROOT))


def _events_df(uid: Optional[str] = None) -> pd.DataFrame:
    df = pd.DataFrame(json.loads(DATA.read_text(encoding="utf-8")))
    if uid is not None:
        df = df[df["uid"] == uid]
    if df.empty:
        return df
    df = df.sort_values("ts").reset_index(drop=True)
    df["dt"] = pd.to_datetime(df["ts"], unit="s")
    return df


@tool(
    name="chart_account_timeline",
    description=(
        "把某 uid 的事件流画成 PNG 图(上:时间线,按事件类型分道、按 IP 着色、"
        "订单点标金额;下:5 分钟窗口事件数柱状图,叠加监控 burst 阈值线)。"
        "返回文件路径与数字摘要。适合排查单账号行为模式;回答时把路径告诉研究员"
        "即可,不要尝试用文字复述图形。"
    ),
    parameters={
        "type": "object",
        "properties": {"uid": {"type": "string", "description": "用户 ID"}},
        "required": ["uid"],
    },
)
def chart_account_timeline(uid: str):
    df = _events_df(uid)
    if df.empty:
        return {"uid": uid, "found": False}
    types = sorted(df["type"].unique())
    ips = sorted(df["ip"].unique())
    color = {ip: PALETTE[i % len(PALETTE)] for i, ip in enumerate(ips)}

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 6), sharex=True,
                                   height_ratios=[2, 1], constrained_layout=True)
    for ip, g in df.groupby("ip"):
        ax1.scatter(g["dt"], g["type"].map(types.index), s=45, color=color[ip],
                    label=ip, alpha=0.85, edgecolors="none")
    if "amount" in df.columns:
        for _, row in df[df["amount"].notna()].iterrows():
            ax1.annotate("%.1f" % row["amount"], (row["dt"], types.index(row["type"])),
                         textcoords="offset points", xytext=(0, 9), ha="center", fontsize=8)
    ax1.set_yticks(range(len(types)), types)
    ax1.set_ylim(-0.6, len(types) - 0.4)
    ax1.grid(axis="y", color="#eee")
    ax1.legend(title="IP", loc="upper left", bbox_to_anchor=(1.01, 1), fontsize=8)
    ax1.set_title(_t("账号 %s 事件时间线" % uid, "Account %s event timeline" % uid))

    # 下图窗口大小与 account_monitor 默认窗口(300s)对齐,阈值线也来自 monitor,
    # 让"图上看到的"和"监控报的"是同一个口径。
    win = df.set_index("dt").resample("300s").size()
    ax2.bar(win.index, win.values, width=300 / 86400, color="#4e79a7", alpha=0.8)
    ax2.axhline(MONITOR_BURST_MIN, ls="--", lw=1, color="#e15759",
                label=_t("burst 阈值 %d" % MONITOR_BURST_MIN, "burst threshold %d" % MONITOR_BURST_MIN))
    ax2.set_ylabel(_t("5 分钟事件数", "events / 5min"))
    ax2.legend(fontsize=8)
    ax2.grid(axis="y", color="#eee")
    fig.autofmt_xdate()

    path = _save(fig, "timeline_%s.png" % uid)
    return {
        "uid": uid,
        "found": True,
        "chart_path": path,
        "summary": {
            "event_count": len(df),
            "span_seconds": int(df["ts"].max() - df["ts"].min()),
            "distinct_ip": len(ips),
            "distinct_device": int(df["device_id"].nunique()),
            "types": {k: int(v) for k, v in df["type"].value_counts().items()},
            "busiest_window_events": int(win.max()),
        },
    }


@tool(
    name="chart_threshold_sweep",
    description=(
        "对单个规则阈值做扫描回测:逐个候选值跑 rule_backtest,画出 precision/"
        "recall/F1 随阈值变化的曲线(PNG),返回文件路径、逐点指标表与 F1 最优值。"
        "规则调参前先用它看指标对该参数的敏感度。param 可选:"
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
    df = pd.DataFrame(rows)

    fig, ax = plt.subplots(figsize=(8, 4.5), constrained_layout=True)
    # x 用等距类目位置而非数值:扫描序列常跨数量级(5~600),数值轴会挤成一团
    x = range(len(df))
    for i, metric in enumerate(("precision", "recall", "f1")):
        ax.plot(x, df[metric], marker="o", ms=4, lw=2, color=PALETTE[i], label=metric)
    best_i = int(df["f1"].idxmax())
    ax.annotate("best F1=%.3f" % df.loc[best_i, "f1"], (best_i, df.loc[best_i, "f1"]),
                textcoords="offset points", xytext=(0, 12), ha="center", fontsize=9)
    ax.set_xticks(list(x), ["%g" % v for v in df["value"]])
    ax.set_xlabel(param)
    ax.set_ylim(-0.05, 1.1)
    ax.grid(axis="y", color="#eee")
    ax.legend()
    ax.set_title(_t("阈值扫描:%s(口径 flag=review+reject)" % param,
                    "Threshold sweep: %s (flag=review+reject)" % param))

    path = _save(fig, "sweep_%s.png" % param)
    best = rows[best_i]
    return {"param": param, "chart_path": path, "rows": rows,
            "best_by_f1": {"value": best["value"], "f1": best["f1"]}}
