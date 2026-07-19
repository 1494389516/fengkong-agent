# -*- coding: utf-8 -*-
"""关联图谱工具:账号-设备-IP 二部图,连通分量即天然的"疑似团伙"分组。

为什么是图:单账号视角看 u_1003 只是"灰名单设备 + 小额订单",拉成图才能
看到 u_1003/u_1004/u_1005 挂在同一台设备上 —— 团伙结构是关联出来的,
不是单点特征算出来的。连通分量 ID 还可以反哺规则(同分量内有黑账号,
其余成员升灰)。

返回给模型的是分量的结构化描述(成员/资源/名单命中),图渲染成 PNG 给人看。
"""
from typing import Optional

import networkx as nx

from . import tool
from .charts import LABEL_COLORS, PALETTE, _save, _t, plt
from .datasource import load_blacklist, load_events, load_labels

MAX_DRAW_COMPONENTS = 9  # 最多画的分量面板数:每个分量独立一个子图,超出只画最大的前 N 个


def _build_graph() -> nx.Graph:
    g = nx.Graph()
    for e in load_events():
        uid = ("uid", e["uid"])
        g.add_node(uid, kind="uid")
        for kind, key in (("device_id", "device_id"), ("ip", "ip")):
            node = (kind, e[key])
            g.add_node(node, kind=kind)
            g.add_edge(uid, node)
    return g


def _component_info(nodes, blacklisted: dict, labels: dict) -> dict:
    accounts = sorted(v for k, v in nodes if k == "uid")
    return {
        "accounts": accounts,
        "account_count": len(accounts),
        "devices": sorted(v for k, v in nodes if k == "device_id"),
        "ips": sorted(v for k, v in nodes if k == "ip"),
        "blacklist_hits": sorted(
            "%s=%s(%s)" % (k, v, blacklisted[(k, v)]) for k, v in nodes if (k, v) in blacklisted),
        "known_labels": {u: labels[u] for u in accounts if u in labels},
    }


def component_summary(uid: str):
    """某账号所在关联分量的结构化描述(不渲染图)。account_profile 复用;
    找不到该账号返回 None。"""
    g = _build_graph()
    node = ("uid", uid)
    if node not in g:
        return None
    blacklisted = {(r["dimension"], r["value"]): r["list"] for r in load_blacklist()}
    labels = {k: v["label"] for k, v in load_labels().items()}
    return _component_info(nx.node_connected_component(g, node), blacklisted, labels)


@tool(
    name="graph_relations",
    description=(
        "账号-设备-IP 关联图谱:把事件流建成二部图,连通分量作为疑似团伙分组。"
        "不传参数返回所有多账号分量(按账号数降序)+ 全图 PNG;传 uid 只返回该"
        "账号所在分量 + 该分量的 PNG。返回内容含各分量的成员账号、共用设备/IP、"
        "名单命中与已知标签。适合'有没有团伙''这个账号和谁有关联'类问题。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "uid": {"type": "string", "description": "可选:只看该账号所在的关联分量"},
            "min_accounts": {"type": "integer",
                             "description": "分量最少账号数,默认 2(单账号分量不是团伙)"},
        },
    },
)
def graph_relations(uid: Optional[str] = None, min_accounts: int = 2):
    g = _build_graph()
    blacklisted = {(r["dimension"], r["value"]): r["list"] for r in load_blacklist()}
    labels = {k: v["label"] for k, v in load_labels().items()}

    if uid is not None:
        node = ("uid", uid)
        if node not in g:
            return {"uid": uid, "found": False}
        comps = [nx.node_connected_component(g, node)]
    else:
        comps = [c for c in nx.connected_components(g)
                 if sum(1 for k, _ in c if k == "uid") >= max(min_accounts, 1)]
        comps.sort(key=lambda c: -sum(1 for k, _ in c if k == "uid"))

    infos = [_component_info(c, blacklisted, labels) for c in comps]

    chart_path = None
    draw_comps = comps[:MAX_DRAW_COMPONENTS]
    if draw_comps:
        chart_path = _draw(g, draw_comps, blacklisted, labels, uid)

    result = {"components": infos, "component_count": len(infos), "chart_path": chart_path}
    if uid is not None:
        result["uid"] = uid
        result["found"] = True
    if chart_path and len(draw_comps) < len(comps):
        result["chart_note"] = "图中只画账号数最多的前 %d 个分量,完整信息见 components" % len(draw_comps)
    return result


def _draw(g, comps, blacklisted, labels, uid=None) -> str:
    """每个分量一个子图面板(small multiples):分量之间没有边,合画一个坐标系
    只会互相纠缠成毛线球;分开画各自用满空间,标签也不打架。"""
    n = len(comps)
    ncols = min(3, n)
    nrows = (n + ncols - 1) // ncols
    fig, axes = plt.subplots(nrows, ncols, figsize=(5.2 * ncols, 4.4 * nrows),
                             constrained_layout=True, squeeze=False)
    kind_style = {"uid": (PALETTE[0], "o", 520), "device_id": (PALETTE[1], "s", 460),
                  "ip": (PALETTE[3], "^", 260)}
    for ax, comp in zip(axes.flat, comps):
        sub = g.subgraph(comp)
        # k 控制节点间距;节点越少 k 越大,小团伙摊开画
        pos = nx.spring_layout(sub, seed=42, k=1.6 / max(len(sub), 4) ** 0.5)
        nx.draw_networkx_edges(sub, pos, ax=ax, edge_color="#ddd")
        for kind, (color, marker, size) in kind_style.items():
            nodes = [nd for nd in sub if nd[0] == kind]
            if not nodes:
                continue
            colors = [LABEL_COLORS.get(labels.get(nd[1]), color) if kind == "uid" else color
                      for nd in nodes]
            edge_colors = ["#b00" if nd in blacklisted else "#fff" for nd in nodes]
            nx.draw_networkx_nodes(sub, pos, nodelist=nodes, node_color=colors, node_shape=marker,
                                   node_size=size, edgecolors=edge_colors, linewidths=1.8, ax=ax)
        # 标签分两档:账号/设备是主角,白底衬托;IP 是配角,小一号灰字。
        # IP 太多时(bot 轮换池)全标必然糊成一团,只标名单命中的。
        main = {nd: nd[1] for nd in sub if nd[0] != "ip"}
        ips = {nd: nd[1] for nd in sub if nd[0] == "ip"}
        if len(ips) > 10:
            ips = {nd: v for nd, v in ips.items() if nd in blacklisted}
        nx.draw_networkx_labels(sub, pos, labels=main, font_size=8, ax=ax,
                                bbox={"facecolor": "white", "alpha": 0.7, "edgecolor": "none", "pad": 1})
        nx.draw_networkx_labels(sub, pos, labels=ips, font_size=6.5, font_color="#555", ax=ax,
                                verticalalignment="top")
        acc = sum(1 for nd in comp if nd[0] == "uid")
        bl = sum(1 for nd in comp if nd in blacklisted)
        ax.set_title(_t("%d 账号 · %d 名单命中" % (acc, bl),
                        "%d accounts / %d blacklisted" % (acc, bl)), fontsize=9)
        ax.margins(0.18)
        ax.axis("off")
    for ax in axes.flat[n:]:  # 网格里多出来的空面板隐藏
        ax.axis("off")
    fig.suptitle(_t("关联图谱:每个面板一个分量 | 圆=账号(红=fraud 标签) 方=设备 三角=IP | 红描边=名单命中",
                    "Relation graph: one component per panel | circle=uid square=device triangle=ip"),
                 fontsize=10)
    return _save(fig, "relations_%s.png" % (uid or "all"))
