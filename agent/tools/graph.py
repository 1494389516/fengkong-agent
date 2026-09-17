# -*- coding: utf-8 -*-
"""Bounded, point-in-time association evidence; connectivity is not a fraud label.

All IP edges are weak, including mobile and residential shared public exits.
Device identity is an asserted identifier, not proof of a human or exclusive ownership.
"""
import math
import time
from collections import deque
from typing import Optional

import networkx as nx

from . import tool
from .charts import LABEL_COLORS, PALETTE, _save, _t, plt
from .datasource import load_events, load_labels
from .blacklist import active_records
from .intel import device_risk_flags, device_type_summary, ip_info

MAX_DRAW_COMPONENTS = 9  # 最多画的分量面板数:每个分量独立一个子图,超出只画最大的前 N 个

DEFAULT_WINDOW_SECONDS = 30 * 86400
MAX_GRAPH_EVENTS = 50000
MAX_GRAPH_NODES = 5000
MAX_RESOURCE_DEGREE = 20
MAX_COMPONENT_NODES = 100
MAX_COMPONENT_HOPS = 4
MAX_COMPONENTS = 100
MAX_EXPANDED_NODES = 200


def _finite_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _build_graph(as_of_ts=None, window_seconds=DEFAULT_WINDOW_SECONDS) -> nx.Graph:
    anchor = time.time() if as_of_ts is None else as_of_ts
    if not _finite_number(anchor) or not _finite_number(window_seconds) or window_seconds <= 0:
        raise ValueError("as_of_ts must be finite; window_seconds must be positive and finite")
    if window_seconds > 366 * 86400:
        raise ValueError("graph window must not exceed 366 days")
    g = nx.Graph()
    g.graph.update(as_of_ts=anchor, window_seconds=window_seconds, truncated=False,
                   invalid_events=0, interpretation="association_only")
    for index, e in enumerate(load_events()):
        if index >= MAX_GRAPH_EVENTS:
            g.graph["truncated"] = True
            break
        ts = e.get("ts")
        if not _finite_number(ts) or not isinstance(e.get("uid"), str) or not e["uid"]:
            g.graph["invalid_events"] += 1
            continue
        if not anchor - window_seconds <= ts < anchor:
            continue
        uid = ("uid", e["uid"])
        resources = [(k, e[k]) for k in ("device_id", "ip")
                     if isinstance(e.get(k), str) and e[k]]
        if len(set([uid] + resources) - set(g)) + len(g) > MAX_GRAPH_NODES:
            g.graph["truncated"] = True
            break
        g.add_node(uid, kind="uid")
        for resource in resources:
            g.add_node(resource, kind=resource[0])
            previous = g.get_edge_data(uid, resource, {})
            g.add_edge(uid, resource, strong=resource[0] == "device_id",
                       first_seen=min(ts, previous.get("first_seen", ts)),
                       last_seen=max(ts, previous.get("last_seen", ts)),
                       observation_count=previous.get("observation_count", 0) + 1,
                       identity_trust="asserted_identifier",
                       weak_reason="shared_public_exit" if resource[0] == "ip" else None)
    for node in list(g):
        if node[0] == "device_id" and g.degree(node) > MAX_RESOURCE_DEGREE:
            for neighbor in g[node]:
                g[node][neighbor].update(strong=False, weak_reason="high_degree_resource")
    return g


def _bounded_component(sg, node):
    found = {node}
    queue = deque([(node, 0)])
    truncated = False
    while queue:
        current, depth = queue.popleft()
        for neighbor in sorted(sg[current]):
            if neighbor in found:
                continue
            if depth >= MAX_COMPONENT_HOPS or len(found) >= MAX_COMPONENT_NODES:
                truncated = True
                continue
            found.add(neighbor)
            queue.append((neighbor, depth + 1))
    return found, truncated


def _active_blacklist(g):
    # Shared list-service semantics, including expiry boundaries, with one anchor.
    hits, evidence = {}, []
    for kind, value in g:
        for record in active_records(kind, value, g.graph["as_of_ts"], lists=("black", "gray")):
            key = (kind, value)
            if hits.get(key) != "black":
                hits[key] = record["list"]
            evidence.append({"dimension": kind, "value": value, "list": record["list"],
                             "added_at": record.get("added_at"),
                             "expires_at": record.get("expires_at"),
                             "as_of_ts": g.graph["as_of_ts"]})
    return hits, evidence


def _contextual_info(g, strong, expanded, blacklisted, labels, evidence, truncated=False):
    info = _component_info(strong, expanded, blacklisted, labels)
    info.update(g.graph)
    info["truncated"] = bool(truncated or g.graph["truncated"])
    info["blacklist_evidence"] = [r for r in evidence if (r["dimension"], r["value"]) in expanded]
    info["edge_evidence"] = [dict(source=list(u), target=list(v), **d)
                             for u, v, d in g.subgraph(expanded).edges(data=True)]
    info["limitations"] = ["Connectivity is association only, not a malicious label.",
                           "Device identifiers do not establish exclusive physical ownership.",
                           "Device flags and known labels are current annotations, not historical evidence."]
    return info


def _strong_subgraph(g: nx.Graph) -> nx.Graph:
    sg = nx.Graph()
    sg.add_nodes_from(g.nodes(data=True))
    sg.add_edges_from((u, v) for u, v, d in g.edges(data=True) if d["strong"])
    return sg


def _expand_weak(g: nx.Graph, strong_nodes) -> set:
    """Display-only resources are capped too; truncation is visible in evidence."""
    ext = set(strong_nodes)
    for nd in sorted(strong_nodes):
        if nd[0] == "uid":
            for resource in sorted(g[nd]):
                if resource in ext:
                    continue
                if len(ext) >= MAX_EXPANDED_NODES:
                    g.graph["truncated"] = True
                    return ext
                ext.add(resource)
    return ext


def _component_info(strong_nodes, all_nodes, blacklisted: dict, labels: dict) -> dict:
    accounts = sorted(v for k, v in strong_nodes if k == "uid")
    devices = sorted(v for k, v in strong_nodes if k == "device_id")
    strong_ips = {v for k, v in strong_nodes if k == "ip"}
    return {
        "accounts": accounts,
        "account_count": len(accounts),
        "devices": devices,
        "device_flags": {d: device_risk_flags(d) for d in devices},
        "device_summary": device_type_summary(devices),
        "ips": sorted(strong_ips),
        "weak_ips": sorted(v for k, v in all_nodes if k == "ip" and v not in strong_ips),
        "blacklist_hits": sorted(
            "%s=%s(%s)" % (k, v, blacklisted[(k, v)]) for k, v in all_nodes if (k, v) in blacklisted),
        "known_labels": {u: labels[u] for u in accounts if u in labels},
    }


def component_summary(uid: str, as_of_ts=None, window_seconds=DEFAULT_WINDOW_SECONDS):
    """Bounded association neighborhood at [as_of-window, as_of); absent account -> None."""
    g = _build_graph(as_of_ts, window_seconds)
    node = ("uid", uid)
    if node not in g:
        return None
    blacklisted, evidence = _active_blacklist(g)
    # Label/intelligence snapshots are not versioned; omit them in historical replay.
    labels = {} if as_of_ts is not None else {k: v["label"] for k, v in load_labels().items()}
    strong, truncated = _bounded_component(_strong_subgraph(g), node)
    info = _contextual_info(g, strong, _expand_weak(g, strong), blacklisted, labels, evidence, truncated)
    if as_of_ts is not None:
        info["device_flags"] = {}
        info["device_summary"] = {"status": "historical_snapshot_unavailable"}
    return info


@tool(
    name="graph_relations",
    description=(
        "账号-设备-IP 时窗关联证据:连通性不是恶意标签。所有 IP 为弱边；"
        "设备高连接度弱化，关联扩张有预算。"
        "不传参返回多账号分量(按账号数降序)+ PNG;传 uid 或 device_id 只返回"
        "该节点所在分量。返回含成员、设备/IP、device_flags、名单、标签、"
        "edge_evidence 与时间边界；成员处置不从连通性推导。有设备关联问题直接调,"
        "不要先体检,不要再拆 device_intel/ip_intel,不要对成员逐个档案。"
        "未点名写入时不要 blacklist_add。目标 uid 已判不存在时不要再调。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "uid": {"type": "string", "description": "可选:只看该账号所在分量"},
            "device_id": {"type": "string", "description": "可选:只看该设备所在分量"},
            "as_of_ts": {"type": "number", "description": "取证时点(unix秒)，默认当前时间"},
            "window_seconds": {"type": "integer", "description": "历史窗口秒数，默认30天，最多366天"},
            "min_accounts": {"type": "integer",
                             "description": "关联分量最少账号数,默认 2"},
        },
    },
)
def graph_relations(uid: Optional[str] = None, device_id: Optional[str] = None,
                    min_accounts: int = 2, as_of_ts=None,
                    window_seconds=DEFAULT_WINDOW_SECONDS):
    if uid and device_id:
        return {"error": "uid 与 device_id 不要同时传;设备问题用 device_id"}
    g = _build_graph(as_of_ts, window_seconds)
    sg = _strong_subgraph(g)
    blacklisted, evidence = _active_blacklist(g)
    labels = {} if as_of_ts is not None else {k: v["label"] for k, v in load_labels().items()}
    component_truncation = []


    if uid is not None or device_id is not None:
        kind, val = ("uid", uid) if uid is not None else ("device_id", device_id)
        node = (kind, val)
        if node not in g:
            return {kind: val, "found": False, "next_action": "stop",
                    "as_of_ts": g.graph["as_of_ts"], "window_seconds": window_seconds,
                    "truncated": g.graph["truncated"],
                    "stop_reason": "当前时窗图中无此 %s，不代表全历史不存在。"
                    % kind}
        component, truncated = _bounded_component(sg, node)
        comps = [component]
        component_truncation = [truncated]
    else:
        comps, seen = [], set()
        for node in sorted(sg):
            if node[0] != "uid" or node in seen:
                continue
            component, truncated = _bounded_component(sg, node)
            seen.update(component)
            if sum(k == "uid" for k, _ in component) >= max(min_accounts, 1):
                comps.append(component)
                component_truncation.append(truncated)
            if len(comps) >= MAX_COMPONENTS:
                g.graph["truncated"] = True
                break

    expanded = [_expand_weak(g, c) for c in comps]
    infos = [_contextual_info(g, c, e, blacklisted, labels, evidence, t)
             for c, e, t in zip(comps, expanded, component_truncation)]
    for info in infos:
        # Existing verdict_brief consumes all history and cannot support this time domain.
        info["member_verdicts"] = {}
        info["member_verdicts_status"] = "unavailable_in_graph_time_domain"
        if as_of_ts is not None:
            info["device_flags"] = {}
            info["device_summary"] = {"status": "historical_snapshot_unavailable"}

    chart_path = None
    draw_comps = expanded[:MAX_DRAW_COMPONENTS]
    if draw_comps:
        chart_path = _draw(g, draw_comps, blacklisted, labels, uid or device_id)

    result = {"components": infos, "component_count": len(infos), "chart_path": chart_path,
              "next_action": "answer",
              "stop_reason": "这是限定时窗关联证据，不是成员恶意判定。",
              "as_of_ts": g.graph["as_of_ts"], "window_seconds": window_seconds,
              "truncated": g.graph["truncated"] or any(component_truncation),
              "interpretation": "association_only"}
    if uid is not None:
        result["uid"] = uid
        result["found"] = True
    if device_id is not None:
        result["device_id"] = device_id
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
                    "虚线+淡色三角=IP弱关联(不作并组依据)",
                    "Relation graph: one component per panel | dashed+pale = weak association (not a grouping edge)"),
                 fontsize=10)
    return _save(fig, "relations_%s.png" % (uid or "all"))
