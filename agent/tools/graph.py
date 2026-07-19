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

MAX_DRAW_NODES = 80  # 画图节点上限:超出只画账号数最多的前几个分量,避免毛线球


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

    # 画图:节点数超限时只画前几个大分量,信息全量在返回值里
    draw_comps, drawn_nodes = [], 0
    for c in comps:
        if drawn_nodes + len(c) > MAX_DRAW_NODES and draw_comps:
            break
        draw_comps.append(c)
        drawn_nodes += len(c)
    chart_path = None
    if draw_comps:
        sub = g.subgraph(set().union(*draw_comps))
        pos = nx.spring_layout(sub, seed=42)
        fig, ax = plt.subplots(figsize=(9, 7), constrained_layout=True)
        kind_style = {"uid": (PALETTE[0], "o"), "device_id": (PALETTE[1], "s"), "ip": (PALETTE[3], "^")}
        nx.draw_networkx_edges(sub, pos, ax=ax, edge_color="#ccc")
        for kind, (color, marker) in kind_style.items():
            nodes = [n for n in sub if n[0] == kind]
            colors = [LABEL_COLORS.get(labels.get(n[1]), color) if kind == "uid" else color
                      for n in nodes]
            edge_colors = ["#b00" if n in blacklisted else "#fff" for n in nodes]
            nx.draw_networkx_nodes(sub, pos, nodelist=nodes, node_color=colors, node_shape=marker,
                                   node_size=420, edgecolors=edge_colors, linewidths=1.6, ax=ax)
        nx.draw_networkx_labels(sub, pos, labels={n: n[1] for n in sub}, font_size=7, ax=ax)
        ax.set_title(_t("账号(圆)-设备(方)-IP(三角)关联图;红描边=名单命中",
                        "uid(circle)-device(square)-ip(triangle) graph; red outline = blacklisted"))
        ax.axis("off")
        chart_path = _save(fig, "relations_%s.png" % (uid or "all"))

    result = {"components": infos, "component_count": len(infos), "chart_path": chart_path}
    if uid is not None:
        result["uid"] = uid
        result["found"] = True
    if chart_path and len(draw_comps) < len(comps):
        result["chart_note"] = "图中只画了前 %d 个分量(节点数限制),完整信息见 components" % len(draw_comps)
    return result
