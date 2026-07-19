# -*- coding: utf-8 -*-
"""图表工具:matplotlib + pandas 渲染 PNG,落盘到 out/charts/。

设计约定(为什么这样设计):
- 图是给人看的,模型看不了图 —— 返回给模型的只有"文件路径 + 数字摘要",
  序列原文与图形本体绝不进对话上下文(那是 token 爆炸的重灾区)。
- 无头环境用 Agg 后端(必须在 pyplot 导入前设置)。
- 中文标题依赖 CJK 字体,启动时探测,探测不到回退英文标题 ——
  图内数据文本(uid/ip/事件类型/指标名)本来就是 ASCII,不受影响。
"""
from pathlib import Path
from typing import List, Optional

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402
import seaborn as sns  # noqa: E402

from . import tool  # noqa: E402
from .backtest import account_verdicts, backtest  # noqa: E402
from .blacklist import blacklist_query  # noqa: E402
from .datasource import load_accounts, load_events, load_labels, load_reports  # noqa: E402
from .featurelib import account_features, batch_features, behavior_paths, percentile_rank  # noqa: E402
from .intel import device_type_summary, ip_info, ip_type_summary  # noqa: E402
from .monitor import account_monitor  # noqa: E402
from .policy import active_policy  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent.parent
OUT = ROOT / "out" / "charts"

# chart_cohort_features 的特征列(列名与 featurelib.batch_features 对齐)
FEATURE_COLS = ["event_count", "distinct_ip", "distinct_device", "coupon_claims",
                "order_amount_max", "min_gap_seconds", "shared_device_accounts"]
LABEL_COLORS = {"fraud": "#e15759", "normal": "#4e79a7", "unlabeled": "#bab0ac"}

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
    "r003_cashout_window_seconds": [600, 1800, 3600, 7200, 14400],
    "r004_max_account_age_seconds": [3600, 86400, 259200, 604800, 1209600],
    "r004_min_amount": [50, 100, 200, 500, 1000],
    "r005_min_register_score": [40, 60, 70, 80, 90],
    "r005_max_account_age_seconds": [86400, 259200, 604800, 1209600],
    "r006_reject_emulator": [0, 1],
    "r006_reject_rooted": [0, 1],
    "r006_reject_hook": [0, 1],
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
    df = pd.DataFrame(load_events())
    if uid is not None:
        df = df[df["uid"] == uid]
    if df.empty:
        return df
    df = df.sort_values("ts").reset_index(drop=True)
    df["dt"] = pd.to_datetime(df["ts"], unit="s")
    return df


# 基线百分位面板的特征集:(键, 中文名, 低值可疑, 对应阈值的 policy 键)
PCT_FEATURES = [
    ("event_count", "事件数", False, "r002_min_events"),
    ("distinct_ip", "去重 IP", False, None),
    ("coupon_claims", "领券数", False, None),
    ("order_amount_max", "最大订单", False, "r003_high_amount"),
    ("min_gap_seconds", "最短间隔(低=可疑)", True, "r002_max_gap_seconds"),
]

VERDICT_COLOR = {"reject": "#b00020", "review": "#e07b00", "pass": "#2a7d4f"}


def _draw_profile_header(ax, uid, feats, verdict):
    """档案栏:注册上下文 / 价值与判定 / 活跃与信号 —— 回答'这个账号是谁'。"""
    from .profile import _value_tier  # 惰性导入避开 charts<->graph<->profile 环
    ax.axis("off")
    acct = load_accounts().get(uid)
    clock = max((e["ts"] for e in load_events()), default=0)
    lines = []
    if acct:
        reg_hit = any(r["list"] != "white" and not r.get("expired")
                      for d, v in (("ip", acct.get("register_ip")),
                                   ("device_id", acct.get("register_device"))) if v
                      for r in blacklist_query(d, v)["records"])
        kyc_names = {0: "未认证", 1: "手机实名", 2: "身份证实名"}
        os_txt = ("%s %s" % (acct.get("register_os", "?"),
                             acct.get("register_os_version", ""))).strip()
        lines.append((_t("注册:%s(账龄 %d 天)· 渠道:%s · 注册方式:%s · 系统:%s · KYC:%s · 换绑:%d 次%s" % (
            pd.to_datetime(acct["registered_at"], unit="s").strftime("%Y-%m-%d"),
            (clock - acct["registered_at"]) // 86400, acct["register_channel"],
            acct["register_method"], os_txt,
            kyc_names.get(acct["kyc_level"], acct["kyc_level"]),
            acct.get("phone_rebind_count", 0),
            " · [!]注册环境命中名单" if reg_hit else ""),
            "registered %s" % acct["registered_at"]), "#333"))
        # 价值分档走 profile 的单一实现,阈值(1000/100)不在这里重钉一份
        vt = _value_tier(acct.get("ltv", 0.0))
        tier_note = {"high": "误伤代价高", "medium": "误伤代价中", "low": "误伤代价低"}[vt["tier"]]
        wl = any(r["list"] == "white" and not r.get("expired")
                 for r in blacklist_query("uid", uid)["records"])
        lines.append((_t("价值:LTV %.0f · 档位:%s(%s)%s" % (
            vt["ltv"], vt["tier"], tier_note,
            " · 白名单账号(行为规则抑制,reject 降档 review)" if wl else ""),
            "LTV %.0f" % vt["ltv"]), "#2a7d4f" if wl else "#333"))
    else:
        lines.append((_t("无账号主档(注册信息缺失)", "no account record"), "#999"))
    reports_v = sum(1 for r in load_reports()
                    if r.get("reported_uid") == uid and r.get("status") == "verified")
    lines.append((_t("事件:%d · 活跃跨度:%.1f 天 · IP:%d(%s)· 设备:%d(%s)· 属实举报:%d" % (
        feats["event_count"], feats["span_seconds"] / 86400, feats["distinct_ip"],
        "/".join("%s×%d" % kv for kv in ip_type_summary(feats["ips"]).items()),
        feats["distinct_device"],
        "/".join("%s×%d" % kv for kv in device_type_summary(feats["devices"]).items()),
        reports_v),
        "activity"), "#333"))
    # 行为路径:会话级序列签名(套现/盗号/bot 各有语法),直奔下单的间隔单独点名
    bp = behavior_paths(uid)
    if bp.get("found"):
        path_txt = " | ".join("%s(%d 次)" % (p["path"], p["count"])
                              for p in bp["top_paths"][:3])
        l2o = bp.get("login_to_order_min_seconds")
        if l2o is not None:
            path_txt += _t(" · 登录→下单最短 %d 分钟" % (l2o // 60),
                           " login->order min %dm" % (l2o // 60))
        lines.append((_t("路径:%s" % path_txt, "paths: %s" % path_txt), "#555"))
    for i, (text, c) in enumerate(lines):
        ax.text(0.0, 0.95 - 0.25 * i, text, fontsize=9.5, color=c, va="top")
    ax.text(1.0, 0.92, _t("判定 %s" % verdict["predicted"].upper(),
                          verdict["predicted"].upper()),
            fontsize=13, fontweight="bold", ha="right", va="top",
            color=VERDICT_COLOR.get(verdict["predicted"], "#333"))
    ax.text(1.0, 0.50, _t("命中 %s" % ("、".join(verdict["rules"]) or "无"),
                          ",".join(verdict["rules"]) or "-"),
            fontsize=9, ha="right", va="top", color="#555")
    score = (acct or {}).get("register_risk_score")
    if score is not None:
        sc = "#b00020" if score >= 70 else ("#e07b00" if score >= 40 else "#2a7d4f")
        ax.text(1.0, 0.16, _t("注册风险分 %d" % score, "reg risk %d" % score),
                fontsize=10, fontweight="bold", ha="right", va="top", color=sc)


def _draw_baseline_panel(ax, feats):
    """特征 vs 人群基线:横条 = 该账号的人群百分位;黑色竖标 = 现行阈值折算成的
    百分位位置 —— 一眼看出'这个账号在人群什么水位、离阈值多远'。"""
    pol = active_policy()
    rows = [(f, label, low_bad, thr) for f, label, low_bad, thr in PCT_FEATURES
            if feats.get(f) is not None]
    for i, (f, label, low_bad, thr_key) in enumerate(rows):
        val = feats[f]
        pct = (percentile_rank(f, val) or 0) * 100
        # 可疑方向因特征而异:低值可疑的特征(最短间隔)只在低分位标红,
        # 高分位是"比谁都慢"= 正常
        extreme = (pct <= 10) if low_bad else (pct >= 95)
        ax.barh(i, pct, height=0.55, color="#e15759" if extreme else "#4e79a7", alpha=0.85)
        ax.text(min(pct + 2, 70), i, _t("%s=%g · P%.0f" % (label, val, pct),
                                        "%s=%g P%.0f" % (f, val, pct)),
                fontsize=8, va="center")
        if thr_key:
            tp = (percentile_rank(f, pol[thr_key]) or 0) * 100
            ax.plot([tp], [i], marker="|", ms=20, color="#222", zorder=5)
            ax.text(tp, i - 0.42, _t("阈值", "thr"), fontsize=6.5, ha="center", color="#222")
    ax.set_yticks([])
    ax.set_xlim(0, 108)
    ax.set_xlabel(_t("人群百分位(%)", "population percentile (%)"), fontsize=8)
    ax.invert_yaxis()
    ax.grid(axis="x", color="#eee")
    ax.set_title(_t("特征 vs 人群基线(| = 现行阈值水位)",
                    "features vs population baseline"), fontsize=9)


@tool(
    name="chart_account_timeline",
    description=(
        "单账号监控仪表盘(PNG)。顶部档案栏:注册时间/账龄/渠道/KYC/换绑/注册环境"
        "名单联查、LTV 价值分档(误伤代价)、活跃摘要(事件数/跨度/IP 类型分布/"
        "属实举报)、当前判定与命中规则;左侧时间线:按类型分道、按 IP 着色(图例带"
        "情报类型)、订单标金额、地理跳变红箭头、异常窗口红纹+信号名 + 5 分钟窗口"
        "事件数与 burst 阈值线;右侧:各特征的人群百分位横条与现行阈值水位标记"
        "(基线对比 + 阈值对比)。返回文件路径、信号列表与数字摘要。"
        "回答时把路径告诉研究员即可,不要尝试用文字复述图形。"
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
    mon = account_monitor(uid)  # 图上画的 = 监控报的,同一份口径
    signals = mon.get("signal_types", [])
    jumps = mon.get("geo_jumps", [])
    feats = account_features(uid)
    verdict = account_verdicts([uid], load_events())[uid]
    types = sorted(df["type"].unique())
    ips = sorted(df["ip"].unique())
    color = {ip: PALETTE[i % len(PALETTE)] for i, ip in enumerate(ips)}

    fig = plt.figure(figsize=(12.5, 8.5), constrained_layout=True)
    gs = fig.add_gridspec(3, 5, height_ratios=[0.72, 2.1, 1.0])
    ax_info = fig.add_subplot(gs[0, :])
    ax1 = fig.add_subplot(gs[1, :3])
    ax_pct = fig.add_subplot(gs[1:, 3:])
    ax2 = fig.add_subplot(gs[2, :3], sharex=ax1)

    _draw_profile_header(ax_info, uid, feats, verdict)
    _draw_baseline_panel(ax_pct, feats)
    # 每个 IP 一条微偏移的水平条带:bot 轮换 IP 时点会精确重叠,不偏移就只剩最后画的颜色
    off_step = min(0.09, 0.5 / max(len(ips), 1))
    ip_off = {ip: (i - (len(ips) - 1) / 2) * off_step for i, ip in enumerate(ips)}
    for ip, g in df.groupby("ip"):
        info = ip_info(ip)  # 图例带情报类型:同样的 IP 数,家宽和机房是两个物种
        label = ip if info["type"] == "unknown" else "%s (%s)" % (ip, info["type"])
        ax1.scatter(g["dt"], g["type"].map(types.index) + ip_off[ip], s=45, color=color[ip],
                    label=label, alpha=0.85, edgecolors="none")
    if "amount" in df.columns:
        for _, row in df[df["amount"].notna()].iterrows():
            ax1.annotate("%.1f" % row["amount"], (row["dt"], types.index(row["type"])),
                         textcoords="offset points", xytext=(0, 9), ha="center", fontsize=8)
    # 地理跳变:红色箭头横跨两次事件,标注城市与不可能的速度
    for j in jumps:
        x0 = pd.to_datetime(j["from_ts"], unit="s")
        x1 = pd.to_datetime(j["to_ts"], unit="s")
        y = len(types) - 0.25
        ax1.annotate("", xy=(x1, y), xytext=(x0, y),
                     arrowprops={"arrowstyle": "->", "color": "#b00", "lw": 1.6})
        ax1.annotate(_t("地理跳变 %s→%s %d km/h" % (j["from_city"], j["to_city"], j["speed_kmh"]),
                        "geo jump %s->%s %d km/h" % (j["from_city"], j["to_city"], j["speed_kmh"])),
                     (x0 + (x1 - x0) / 2, y), textcoords="offset points", xytext=(0, 7),
                     ha="center", fontsize=8.5, color="#b00")
    ax1.set_yticks(range(len(types)), types)
    ax1.set_ylim(-0.6, len(types) - 0.4 + (0.55 if jumps else 0))
    ax1.grid(axis="y", color="#eee")
    ax1.legend(title="IP", loc="upper left", fontsize=7, title_fontsize=8, framealpha=0.85)

    # 下图窗口大小与 account_monitor 默认窗口(300s)对齐;burst 阈值线在
    # 画图时从 policy 现取(不能 import 时冻结,否则版本更新后图线和监控口径分叉)。
    burst_min = active_policy()["monitor_burst_min"]
    win = df.set_index("dt").resample("300s").size()
    ax2.bar(win.index, win.values, width=300 / 86400, color="#4e79a7", alpha=0.8)
    ax2.axhline(burst_min, ls="--", lw=1, color="#e15759",
                label=_t("burst 阈值 %d" % burst_min, "burst threshold %d" % burst_min))
    # 监控命中的异常窗口:两图同步红色底纹,窗口上方标信号名
    ymax = max(float(win.max()), burst_min) * 1.15
    for aw in mon.get("anomalous_windows", []):
        x0 = pd.to_datetime(aw["window_start_ts"], unit="s")
        x1 = pd.to_datetime(aw["window_start_ts"] + mon["window_seconds"], unit="s")
        for ax in (ax1, ax2):
            ax.axvspan(x0, x1, color="#e15759", alpha=0.10, zorder=0)
        ax2.annotate(",".join(aw["signals"]), (x0, ymax * 0.92),
                     fontsize=7, color="#b00")
    ax2.set_ylim(0, ymax)
    ax2.set_ylabel(_t("5 分钟事件数", "events / 5min"))
    ax2.legend(fontsize=8, loc="upper right")
    ax2.grid(axis="y", color="#eee")
    plt.setp(ax1.get_xticklabels(), visible=False)
    plt.setp(ax2.get_xticklabels(), rotation=25, ha="right")
    fig.suptitle(_t("账号 %s 监控仪表盘 | 信号: %s" % (uid, "、".join(signals) or "无"),
                    "Account %s monitor dashboard | signals: %s" % (uid, ",".join(signals) or "none")),
                 fontsize=12)

    path = _save(fig, "timeline_%s.png" % uid)
    return {
        "uid": uid,
        "found": True,
        "chart_path": path,
        "signals": signals,
        # 数字摘要复用 featurelib 的 feats(单一事实源),不从 df 另算一份 ——
        # 避免"图上的数"和"特征层的数"两处口径漂移;窗口峰值是图独有的才留 df
        "summary": {
            "event_count": feats["event_count"],
            "span_seconds": int(feats["span_seconds"]),
            "distinct_ip": feats["distinct_ip"],
            "distinct_device": feats["distinct_device"],
            "types": feats["event_types"],
            "busiest_window_events": int(win.max()),
        },
    }


@tool(
    name="chart_threshold_sweep",
    description=(
        "对单个规则阈值扫描回测:逐候选值画 precision/recall/F1 曲线 + 该规则"
        "自身命中归因曲线(命中欺诈/误伤正常,右轴)。aggregate_insensitive=true "
        "= 聚合指标全程无变化(被其他规则遮蔽/无边界样本),无 best 值;"
        "nothing_to_plot=true = 连归因也平直,不出图,把 note 原因转告研究员。"
        "可选参数见 param 枚举。"
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
    # 参数命名约定 rNNN_* -> 所属规则:聚合指标之外必须看"该规则自己命中了谁"。
    # 教训:小样本上其他规则(名单/指纹/金额)把欺诈账号全兜住,扫这条规则的
    # 参数时聚合 F1 恒 1.0 —— 图一条平线还标着 best F1,等于宣称"随便设都最优"。
    rule_id = param.split("_")[0].upper()
    rows = []
    for v in values:
        r = backtest({param: v})
        m = r["operating_points"]["flag=review+reject"]
        per = list(r["per_account"].values())
        rows.append({
            "value": v, "precision": m["precision"], "recall": m["recall"], "f1": m["f1"],
            # 归因:该规则命中的欺诈数(覆盖)与正常数(误伤)——聚合被遮蔽时
            # 这两条曲线仍能显示参数的真实作用面
            "rule_hits_fraud": sum(1 for a in per
                                   if a["label"] == "fraud" and rule_id in a["rules"]),
            "rule_hits_normal": sum(1 for a in per
                                    if a["label"] == "normal" and rule_id in a["rules"]),
        })
    df = pd.DataFrame(rows)
    # 钝感检测:聚合线纹丝不动 = 参数作用被其他规则遮蔽,或数据集没有
    # 该参数的边界样本。此时"最优值"是幻觉,必须显式说出来
    flat = int(df[["precision", "recall", "f1"]].nunique().max()) == 1
    attr_flat = int(df[["rule_hits_fraud", "rule_hits_normal"]].nunique().max()) == 1
    if flat and attr_flat:
        # 连归因曲线都不动:这张图没有任何信息量,画出来就是误导 —— 不出图,
        # 把"为什么无可画"直接当结果返回(研究员实锤过:平线图纯瞎扯淡)
        return {
            "param": param, "rule_id": rule_id, "aggregate_insensitive": True,
            "nothing_to_plot": True, "accounts_evaluated": len(per),
            "rows": rows[:2],  # 留两行证明确实扫过
            "note": ("扫描区间内聚合指标与 %s 归因曲线全部无变化,不出图。"
                     "原因:当前数据集(%d 账号)没有该参数的边界样本,或其作用被"
                     "其他规则完全遮蔽。请换更大数据集(FK_DATASET=gen)或先用 "
                     "rule_backtest 确认该规则在此数据集上有独立命中"
                     % (rule_id, len(per))),
        }

    fig, ax = plt.subplots(figsize=(8, 4.5), constrained_layout=True)
    # x 用等距类目位置而非数值:扫描序列常跨数量级(5~600),数值轴会挤成一团
    x = range(len(df))
    for i, metric in enumerate(("precision", "recall", "f1")):
        ax.plot(x, df[metric], marker="o", ms=4, lw=2, color=PALETTE[i], label=metric)
    ax2 = ax.twinx()
    ax2.plot(x, df["rule_hits_fraud"], marker="s", ms=4, lw=1.6, ls="--", color="#7b1fa2",
             label=_t("%s 命中欺诈(右轴)" % rule_id, "%s hits fraud (right)" % rule_id))
    ax2.plot(x, df["rule_hits_normal"], marker="x", ms=6, lw=1.6, ls=":", color="#e07b00",
             label=_t("%s 误伤正常(右轴)" % rule_id, "%s hits normal (right)" % rule_id))
    ax2.set_ylabel(_t("%s 命中账号数" % rule_id, "%s hit accounts" % rule_id), fontsize=9)
    ax2.set_ylim(bottom=0)
    ax2.yaxis.get_major_locator().set_params(integer=True)
    if flat:
        ax.annotate(_t("聚合指标对该参数不敏感:作用被其他规则遮蔽或无边界样本\n"
                       "以右轴规则归因曲线为准;勿据此选'最优阈值'",
                       "aggregate metrics insensitive to this param\n(masked by other rules "
                       "or no boundary cases); see rule-attribution curves"),
                    (0.5, 0.55), xycoords="axes fraction", ha="center", fontsize=10,
                    color="#b00020",
                    bbox={"boxstyle": "round", "fc": "#fff3f3", "ec": "#b00020"})
    else:
        best_i = int(df["f1"].idxmax())
        ax.annotate("best F1=%.3f" % df.loc[best_i, "f1"], (best_i, df.loc[best_i, "f1"]),
                    textcoords="offset points", xytext=(0, 12), ha="center", fontsize=9)
    h1, l1 = ax.get_legend_handles_labels()
    h2, l2 = ax2.get_legend_handles_labels()
    ax.legend(h1 + h2, l1 + l2, fontsize=8, loc="center right")
    ax.set_xticks(list(x), ["%g" % v for v in df["value"]])
    ax.set_xlabel(param)
    ax.set_ylim(-0.05, 1.1)
    ax.grid(axis="y", color="#eee")
    ax.set_title(_t("阈值扫描:%s(口径 flag=review+reject)" % param,
                    "Threshold sweep: %s (flag=review+reject)" % param))

    path = _save(fig, "sweep_%s.png" % param)
    out = {"param": param, "rule_id": rule_id, "chart_path": path, "rows": rows,
           "aggregate_insensitive": flat}
    if flat:
        out["note"] = ("聚合指标在整个扫描区间无变化:该参数的作用被其他规则遮蔽,"
                       "或当前数据集没有它的边界样本。不存在'最优值';请看 rows 里"
                       "rule_hits_* 归因,或换更大数据集(FK_DATASET=gen)再扫")
    else:
        best = rows[int(df["f1"].idxmax())]
        out["best_by_f1"] = {"value": best["value"], "f1": best["f1"]}
    return out


def _labels() -> dict:
    return {k: v["label"] for k, v in load_labels().items()}


def _account_features() -> pd.DataFrame:
    """逐账号特征表:featurelib 统一特征层 + 标签,行序:label 分组内按 uid。"""
    feats = batch_features()
    labels = _labels()
    feats["label"] = [labels.get(u, "unlabeled") for u in feats.index]
    return feats.sort_values(["label", "uid"])


MAX_COHORT_ROWS = 40  # 大数据集下热力图行数上限,超出取事件数 top-N,返回值里注明


@tool(
    name="chart_cohort_features",
    description=(
        "全量账号群体对比图(PNG,seaborn):上图为账号×特征热力图(颜色=列内"
        "归一化、格内标原始值,行标注 fraud/normal 标签),下图为各账号事件间隔"
        "箱线图(对数轴)。用于跨账号横向对比、找区分欺诈与正常的特征。"
        "返回文件路径与逐账号特征表;注意 min_gap_seconds 越小越可疑。"
    ),
    parameters={"type": "object", "properties": {}},
)
def chart_cohort_features():
    feats = _account_features()
    truncated = None
    if len(feats) > MAX_COHORT_ROWS:
        total = len(feats)
        feats = feats.sort_values("event_count", ascending=False).head(MAX_COHORT_ROWS) \
                     .sort_values(["label", "uid"])
        truncated = "共 %d 账号,图中只画事件数 top %d" % (total, MAX_COHORT_ROWS)
    mat = feats[FEATURE_COLS]
    # 列内 min-max 归一化只管颜色,格内仍标原始值 —— 各列量纲差太多,不归一化热力图就废了
    rng = (mat.max() - mat.min()).replace(0, 1)
    norm = (mat - mat.min()) / rng
    annot = mat.map(lambda v: "-" if pd.isna(v) else "%g" % v)

    # 行数决定画布高度:固定高度下 40 行的行标签必然互相压字
    n_rows = len(feats)
    heat_h = max(2.5, 0.24 * n_rows)
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(11, heat_h + 4.5),
                                   constrained_layout=True, height_ratios=[heat_h, 4])
    sns.heatmap(norm, annot=annot, fmt="", cmap="YlOrRd", cbar=False, linewidths=0.5,
                yticklabels=["%s·%s" % (u, l) for u, l in zip(mat.index, feats["label"])], ax=ax1)
    ax1.set_ylabel("")
    ax1.tick_params(axis="y", rotation=0, labelsize=7 if n_rows > 25 else 9)
    ax1.set_title(_t("账号×特征热力图(颜色=列内归一化;min_gap 越小越可疑)",
                     "Account x feature heatmap (color = per-column normalized)"))

    df = _events_df()
    labels = _labels()
    gdf = df.assign(gap=df.groupby("uid")["ts"].diff()).dropna(subset=["gap"])
    gdf["label"] = gdf["uid"].map(lambda u: labels.get(u, "unlabeled"))
    order = [u for u in feats.index if u in set(gdf["uid"])]
    sns.boxplot(data=gdf, x="uid", y="gap", hue="label", order=order, dodge=False,
                palette=LABEL_COLORS, ax=ax2)
    sns.stripplot(data=gdf, x="uid", y="gap", order=order, color="#333", size=3,
                  alpha=0.6, ax=ax2, legend=False)
    ax2.set_yscale("log")
    ax2.set_xlabel("")
    # 账号多时横轴标签竖排小字,否则互相压字
    ax2.tick_params(axis="x", rotation=90 if len(order) > 12 else 0,
                    labelsize=6.5 if len(order) > 20 else 9)
    ax2.set_ylabel(_t("事件间隔(秒,对数轴)", "event gap (s, log)"))
    ax2.set_title(_t("各账号事件间隔分布", "Per-account event gap distribution"))

    path = _save(fig, "cohort_features.png")
    records = feats.reset_index().astype(object).where(pd.notna(feats.reset_index()), None)
    result = {
        "chart_path": path,
        "accounts": len(feats),
        "features": records.to_dict("records"),
    }
    if truncated:
        result["note"] = truncated
    return result


@tool(
    name="chart_drift_dashboard",
    description=(
        "监控仪表盘 PNG:四面板 —— 特征 PSI 趋势、处置分布(flag 率+输出 PSI)、"
        "近阈带密度(阈值试探)、逐桶欺诈率与特征 IV(区分度衰减)。看趋势用图,"
        "数字明细仍以各监控工具返回为准。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "time_grain": {"type": "string", "enum": ["day", "hour"],
                           "description": "分桶粒度,默认 day"},
        },
    },
)
def chart_drift_dashboard(time_grain: str = "day"):
    """四面板与四个监控工具一一对应:图给人看趋势形状,alert_text 给模型引用。
    任一数据源不足以分桶时对应面板留白标注,不让一个面板拖垮整张图。"""
    from .adversary import adversary_watch
    from .drift import PSI_ALARM, PSI_WATCH, feature_drift, rule_drift
    from .risk import feature_risk

    fd = feature_drift(time_grain=time_grain)
    rd = rule_drift(time_grain=time_grain)
    adv = adversary_watch(time_grain=time_grain)
    fr = feature_risk(time_grain=time_grain)

    fig, axes = plt.subplots(2, 2, figsize=(12.5, 8.5), constrained_layout=True)
    (ax_psi, ax_rule), (ax_near, ax_risk) = axes

    def _blank(ax, msg):
        ax.text(0.5, 0.5, msg, ha="center", va="center", fontsize=10, color="#888")
        ax.axis("off")

    def _legend(ax, size=7):
        if ax.get_legend_handles_labels()[0]:  # 小样本面板可能没有一条可画的线
            ax.legend(fontsize=size)

    alarms = []
    # ① 特征 PSI 趋势
    if fd.get("found"):
        buckets = [b["bucket"] for b in fd["buckets"]]
        x = range(len(buckets))
        for i, (feat, d) in enumerate(fd["features"].items()):
            if any(v is not None for v in d["psi"]):
                ax_psi.plot(x, [v if v is not None else float("nan") for v in d["psi"]],
                            marker="o", ms=3, lw=1.4, label=feat,
                            color=PALETTE[i % len(PALETTE)])
        ax_psi.axhline(PSI_WATCH, ls="--", lw=0.8, color="#aaa")
        ax_psi.axhline(PSI_ALARM, ls="--", lw=0.8, color="#e15759")
        ax_psi.set_xticks(list(x))
        ax_psi.set_xticklabels([b[5:] for b in buckets], fontsize=7, rotation=45)
        _legend(ax_psi)
        ax_psi.set_title(_t("特征 PSI(虚线=关注/告警线)", "feature PSI"), fontsize=10)
        alarms += fd.get("alarms", [])
    else:
        _blank(ax_psi, _t("特征漂移:分桶不足", "feature drift: <2 buckets"))

    # ② 处置分布趋势
    if rd.get("found"):
        tr = rd["verdict_mix"]["trend"]
        xs = range(len(tr))
        ax_rule.plot(xs, [t["flag_rate"] for t in tr], marker="o", ms=3,
                     color=PALETTE[2], label="flag_rate")
        ax_rule.plot(xs, [t.get("psi") if t.get("psi") is not None else float("nan")
                          for t in tr], marker="s", ms=3, color=PALETTE[0], label="verdict PSI")
        ax_rule.set_xticks(list(xs))
        ax_rule.set_xticklabels([t["bucket"][5:] for t in tr], fontsize=7, rotation=45)
        _legend(ax_rule)
        ax_rule.set_title(_t("规则输出:命中率与分布 PSI", "rule output"), fontsize=10)
        alarms += rd.get("alarms", [])
    else:
        _blank(ax_rule, _t("规则输出:分桶不足", "rule drift: <2 buckets"))

    # ③ 近阈带密度
    if adv.get("found"):
        for i, w in enumerate(adv["near_miss"]):
            tr = w["trend"]
            xs = range(len(tr))
            ax_near.plot(xs, [t["rate"] if t["rate"] is not None else float("nan")
                              for t in tr], marker="o", ms=3,
                         color=PALETTE[i % len(PALETTE)],
                         label="%s %s" % (w["rule"], w["feature"]))
            if tr:
                ax_near.set_xticks(list(xs))
                ax_near.set_xticklabels([t["bucket"][5:] for t in tr], fontsize=7, rotation=45)
        _legend(ax_near)
        ax_near.set_title(_t("近阈带密度(阈值试探)", "near-threshold density"), fontsize=10)
        alarms += adv.get("alarms", [])
    else:
        _blank(ax_near, _t("对抗巡检:分桶不足", "adversary: <2 buckets"))

    # ④ 风险趋势:欺诈率 + IV
    trend = fr.get("risk_trend")
    if trend:
        xs = range(len(trend["buckets"]))
        ax_risk.plot(xs, [v if v is not None else float("nan") for v in trend["fraud_rate"]],
                     marker="o", ms=3, color=PALETTE[2], label="fraud_rate")
        for i, (feat, ivs) in enumerate(sorted(trend["iv"].items())[:4]):
            ax_risk.plot(xs, [v if v is not None else float("nan") for v in ivs],
                         marker="s", ms=2.5, lw=1.1, color=PALETTE[(i + 3) % len(PALETTE)],
                         label="IV " + feat)
        ax_risk.set_xticks(list(xs))
        ax_risk.set_xticklabels([b[5:] for b in trend["buckets"]], fontsize=7, rotation=45)
        _legend(ax_risk, 6.5)
        ax_risk.set_title(_t("欺诈率与特征 IV 趋势(衰减=对手在适应)", "risk trend"), fontsize=10)
        alarms += trend.get("decay_alarms", [])
    else:
        _blank(ax_risk, _t("风险趋势:分桶或标签不足", "risk trend: insufficient"))

    fig.suptitle(_t("漂移/对抗/风险 监控仪表盘(%s 粒度)" % time_grain,
                    "monitoring dashboard (%s)" % time_grain), fontsize=11)
    path = _save(fig, "drift_dashboard_%s.png" % time_grain)
    return {"chart_path": path, "time_grain": time_grain,
            "alarm_count": len(alarms), "alarms": alarms[:8],
            "note": "图给人看趋势;数字明细与告警口径以各监控工具返回为准"}
