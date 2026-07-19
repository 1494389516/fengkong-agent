# -*- coding: utf-8 -*-
"""关联图谱工具:账号-设备-IP 二部图,连通分量即天然的"疑似团伙"分组。

为什么是图:单账号视角看 u_1003 只是"灰名单设备 + 小额订单",拉成图才能
看到 u_1003/u_1004/u_1005 挂在同一台设备上 —— 团伙结构是关联出来的,
不是单点特征算出来的。连通分量 ID 还可以反哺规则(同分量内有黑账号,
其余成员升灰)。

返回给模型的是分量的结构化描述(成员/资源/名单命中),图渲染成 PNG 给人看。

边分强弱(教训:随机 IP 撞号曾把互不相干的 bot 与两个团伙并成一组):
- 强边(并组依据):共享设备;共享家宽/基站 IP(物理同址才是身份证据)。
- 弱边(仅展示):机房/代理/未知类型 IP —— 公共出口,陌生人共用是常态,
  拿它并组等于把路人并进案子(超级节点桥接,真实风控的经典事故)。
连通分量只在强边子图上算;弱关联 IP 挂在成员名下画出来(虚线),
并在返回里单列 weak_ips,不冒充团伙纽带。
"""
from typing import Optional

import networkx as nx

from . import tool
from .charts import LABEL_COLORS, PALETTE, _save, _t, plt
from .datasource import load_blacklist, load_events, load_labels
from .intel import ip_info

MAX_DRAW_COMPONENTS = 9  # 最多画的分量面板数:每个分量独立一个子图,超出只画最大的前 N 个

STRONG_IP_TYPES = ("residential", "mobile")  # 物理同址类 IP 才配当并组纽带


def _build_graph() -> nx.Graph:
    g = nx.Graph()
    for e in load_events():
        uid = ("uid", e["uid"])
        g.add_node(uid, kind="uid")
        dev = ("device_id", e["device_id"])
        g.add_node(dev, kind="device_id")
        g.add_edge(uid, dev, strong=True)
        ip = ("ip", e["ip"])
        g.add_node(ip, kind="ip")
        g.add_edge(uid, ip, strong=ip_info(e["ip"])["type"] in STRONG_IP_TYPES)
    return g


def _strong_subgraph(g: nx.Graph) -> nx.Graph:
    sg = nx.Graph()
    sg.add_nodes_from(g.nodes(data=True))
    sg.add_edges_from((u, v) for u, v, d in g.edges(data=True) if d["strong"])
    return sg


def _expand_weak(g: nx.Graph, strong_nodes) -> set:
    """强分量 + 成员账号名下的弱关联 IP(展示用,不参与并组)。"""
    ext = set(strong_nodes)
    for nd in strong_nodes:
        if nd[0] == "uid":
            ext.update(g[nd])
    return ext


def _component_info(strong_nodes, all_nodes, blacklisted: dict, labels: dict) -> dict:
    accounts = sorted(v for k, v in strong_nodes if k == "uid")
    strong_ips = {v for k, v in strong_nodes if k == "ip"}
    return {
        "accounts": accounts,
        "account_count": len(accounts),
        "devices": sorted(v for k, v in strong_nodes if k == "device_id"),
        "ips": sorted(strong_ips),
        "weak_ips": sorted(v for k, v in all_nodes if k == "ip" and v not in strong_ips),
        "blacklist_hits": sorted(
            "%s=%s(%s)" % (k, v, blacklisted[(k, v)]) for k, v in all_nodes if (k, v) in blacklisted),
        "known_labels": {u: labels[u] for u in accounts if u in labels},
    }


def component_summary(uid: str):
    """某账号所在关联分量的结构化描述(不渲染图)。account_profile 复用;
    找不到该账号返回 None。"""
    g = _build_graph()
    node = ("uid", uid)
    if node not in g:
        return None
    # 图上的"名单命中"只标黑/灰(风险);白名单是抑制标注,不该画成红圈
    blacklisted = {(r["dimension"], r["value"]): r["list"] for r in load_blacklist()
                   if r["list"] in ("black", "gray")}
    labels = {k: v["label"] for k, v in load_labels().items()}
    strong = nx.node_connected_component(_strong_subgraph(g), node)
    return _component_info(strong, _expand_weak(g, strong), blacklisted, labels)


@tool(
    name="graph_relations",
    description=(
        "账号-设备-IP 关联图谱:把事件流建成二部图,连通分量作为疑似团伙分组。"
        "并组只认强证据:共享设备、共享家宽/基站 IP;机房/代理 IP 是公共出口,"
        "只在 weak_ips 里展示、不作团伙依据(引用关联结论时说明纽带是什么)。"
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
    sg = _strong_subgraph(g)
    # 图上的"名单命中"只标黑/灰(风险);白名单是抑制标注,不该画成红圈
    blacklisted = {(r["dimension"], r["value"]): r["list"] for r in load_blacklist()
                   if r["list"] in ("black", "gray")}
    labels = {k: v["label"] for k, v in load_labels().items()}

    if uid is not None:
        node = ("uid", uid)
        if node not in g:
            return {"uid": uid, "found": False}
        comps = [nx.node_connected_component(sg, node)]
    else:
        comps = [c for c in nx.connected_components(sg)
                 if sum(1 for k, _ in c if k == "uid") >= max(min_accounts, 1)]
        comps.sort(key=lambda c: -sum(1 for k, _ in c if k == "uid"))

    expanded = [_expand_weak(g, c) for c in comps]
    infos = [_component_info(c, e, blacklisted, labels) for c, e in zip(comps, expanded)]

    chart_path = None
    draw_comps = expanded[:MAX_DRAW_COMPONENTS]
    if draw_comps:
        chart_path = _draw(g, draw_comps, blacklisted, labels, uid)

    result = {"components": infos, "component_count": len(infos), "chart_path": chart_path}
    if uid is not None:
        result["uid"] = uid
        result["found"] = True
    if chart_path and len(draw_comps) < len(comps):
        result["chart_note"] = "图中只画账号数最多的前 %d 个分量,完整信息见 components" % len(draw_comps)
    return result


def _separate(pos, min_dist: float = 0.18, rounds: int = 60) -> None:
    """布局后处理:把间距小于 min_dist 的节点对沿连线方向推开(就地修改 pos)。
    spring 布局对结构等价的节点(同挂一台设备、各带一个 IP 的团伙成员)会给出
    相同坐标 —— 力平衡解重合,节点和标签直接叠死。确定性迭代,无随机源。
    距离按各向异性度量:标签是横向长条,横向相邻需要 ~2 倍于纵向的间隙,
    否则节点分开了标签仍互相压字。"""
    nodes = list(pos)
    for _ in range(rounds):
        moved = False
        for i in range(len(nodes)):
            for j in range(i + 1, len(nodes)):
                a, b = nodes[i], nodes[j]
                dx = float(pos[b][0] - pos[a][0])
                dy = float(pos[b][1] - pos[a][1])
                d = ((dx / 2.2) ** 2 + dy * dy) ** 0.5  # 横向距离打 1/2.2 折算
                if d >= min_dist:
                    continue
                if d < 1e-9:  # 完全重合:按索引给一个确定性的分离方向
                    dx, dy, d = 1.0, float(i - j) * 0.3, 1.0
                push = (min_dist - d) / 2.0 / (d or 1.0)
                pos[a] = (pos[a][0] - dx * push, pos[a][1] - dy * push)
                pos[b] = (pos[b][0] + dx * push, pos[b][1] + dy * push)
                moved = True
        if not moved:
            break


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
        _separate(pos)  # spring 会把结构等价的节点排到同一坐标,标签互相压死
        # 强边实线(并组纽带),弱边虚线(机房/代理 IP 的展示性关联)
        strong_e = [(u, v) for u, v, d in sub.edges(data=True) if d["strong"]]
        weak_e = [(u, v) for u, v, d in sub.edges(data=True) if not d["strong"]]
        nx.draw_networkx_edges(sub, pos, edgelist=strong_e, ax=ax, edge_color="#bbb")
        nx.draw_networkx_edges(sub, pos, edgelist=weak_e, ax=ax, edge_color="#e3e3e3",
                               style="dashed")
        for kind, (color, marker, size) in kind_style.items():
            nodes = [nd for nd in sub if nd[0] == kind]
            if not nodes:
                continue
            if kind == "uid":
                colors = [LABEL_COLORS.get(labels.get(nd[1]), color) for nd in nodes]
            elif kind == "ip":
                # 弱关联 IP(无任何强边)淡化:视觉上就不该和纽带平起平坐
                colors = [color if any(d["strong"] for _, _, d in sub.edges(nd, data=True))
                          else "#cfe0df" for nd in nodes]
            else:
                colors = [color] * len(nodes)
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
    fig.suptitle(_t("关联图谱:每个面板一个分量 | 圆=账号(红=fraud) 方=设备 三角=IP | 红描边=名单命中 | "
                    "虚线+淡色三角=机房/代理 IP(公共出口,不作并组依据)",
                    "Relation graph: one component per panel | dashed+pale = idc/proxy ip (not a grouping edge)"),
                 fontsize=10)
    return _save(fig, "relations_%s.png" % (uid or "all"))
