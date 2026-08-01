# -*- coding: utf-8 -*-
"""
拓扑分层与布局算法（纯函数，不触碰 DB，便于单测）

分层规则（自上而下）：
    border      出口层：防火墙 / 路由器 / 负载均衡
    core        核心层：距出口 1 跳的交换机，或全网度数最大的交换机
    aggregation 汇聚层：距出口 2 跳的交换机
    access      接入层：距出口 ≥3 跳的交换机
    endpoint    终端层：服务器 / 存储 / AP / 打印机 / 未知设备
"""
import re
from collections import defaultdict, deque

LAYER_ORDER = ['border', 'core', 'aggregation', 'access', 'endpoint']

# 设备类型 → 固定层级（交换机不在此表，需按拓扑位置推断）
TYPE_LAYER = {
    'firewall': 'border',
    'router': 'border',
    'loadbalancer': 'border',
    'server': 'endpoint',
    'storage': 'endpoint',
    'printer': 'endpoint',
    'ap': 'endpoint',
    'wlc': 'access',
    'unknown': 'endpoint',
}

# 主机名关键字 → 层级（优先级高于拓扑推断，运维命名通常最准）
NAME_HINTS = [
    (r'core|核心|-co\d|cs\d', 'core'),
    (r'agg|dist|汇聚|as\d', 'aggregation'),
    (r'acc|接入|-sw\d|edge', 'access'),
]

# 画布参数
Y_START = 60
Y_GAP = 150
X_START = 80
X_GAP = 165


def build_adjacency(node_ids, edges):
    """构造邻接表，edges 为 [(src_id, dst_id), ...]"""
    adjacency = defaultdict(set)
    for node_id in node_ids:
        adjacency[node_id] = set()
    for src, dst in edges:
        if src in adjacency and dst in adjacency and src != dst:
            adjacency[src].add(dst)
            adjacency[dst].add(src)
    return adjacency


def assign_layers(nodes, edges):
    """
    为节点分层。

    :param nodes: [{'id':.., 'name':.., 'type_code':..}, ...]
    :param edges: [(src_id, dst_id), ...]
    :return: {node_id: layer_name}
    """
    node_map = {n['id']: n for n in nodes}
    adjacency = build_adjacency(node_map.keys(), edges)
    layers = {}

    # 1) 按设备类型定层
    switches = []
    for node_id, node in node_map.items():
        type_code = (node.get('type_code') or 'unknown').lower()
        if type_code == 'switch':
            switches.append(node_id)
        else:
            layers[node_id] = TYPE_LAYER.get(type_code, 'endpoint')

    # 2) 命名提示优先（对所有节点生效，可纠正类型误判）
    hinted = set()
    for node_id, node in node_map.items():
        name = (node.get('name') or '').lower()
        for pattern, layer in NAME_HINTS:
            if re.search(pattern, name):
                layers[node_id] = layer
                hinted.add(node_id)
                break

    # 3) 剩余交换机按到出口层的跳数推断
    pending = [s for s in switches if s not in hinted]
    if pending:
        roots = [n for n, layer in layers.items() if layer == 'border']
        if not roots:
            # 无出口设备：取度数最大的待定交换机作核心
            roots = [max(pending, key=lambda n: len(adjacency[n]))]
            layers[roots[0]] = 'core'
            pending = [p for p in pending if p != roots[0]]
            depth_base = 0
        else:
            depth_base = 1  # 距出口 1 跳 = 核心

        depth = _bfs_depth(roots, adjacency)
        for node_id in pending:
            hop = depth.get(node_id)
            if hop is None:
                layers[node_id] = 'access'   # 孤立交换机放接入层
                continue
            level = hop - 1 + depth_base
            if level <= 0:
                layers[node_id] = 'core'
            elif level == 1:
                layers[node_id] = 'aggregation'
            else:
                layers[node_id] = 'access'

    # 4) 兜底
    for node_id in node_map:
        layers.setdefault(node_id, 'endpoint')
    return layers


def _bfs_depth(roots, adjacency):
    """从多个根节点出发的最短跳数"""
    depth = {r: 0 for r in roots}
    queue = deque(roots)
    while queue:
        current = queue.popleft()
        for neighbor in adjacency[current]:
            if neighbor not in depth:
                depth[neighbor] = depth[current] + 1
                queue.append(neighbor)
    return depth


def compute_positions(nodes, layers, edges=None):
    """
    计算节点坐标：同层水平排开，整体居中对齐。

    同层内按「相邻上层节点的平均位置」排序，减少连线交叉（重心法一轮足够）。
    :return: {node_id: (x, y)}
    """
    grouped = defaultdict(list)
    for node in nodes:
        grouped[layers.get(node['id'], 'endpoint')].append(node)

    active_layers = [l for l in LAYER_ORDER if grouped.get(l)]
    adjacency = build_adjacency([n['id'] for n in nodes], edges or [])

    positions = {}
    max_count = max((len(grouped[l]) for l in active_layers), default=1)
    canvas_width = max(max_count, 1) * X_GAP

    prev_layer_x = {}
    for layer_idx, layer in enumerate(active_layers):
        members = grouped[layer]

        # 重心排序：按上层邻居的平均 x 排，无邻居的排后面（按名称）
        def sort_key(node):
            neighbors_x = [
                prev_layer_x[n] for n in adjacency[node['id']] if n in prev_layer_x
            ]
            if neighbors_x:
                return (0, sum(neighbors_x) / len(neighbors_x), node.get('name') or '')
            return (1, 0, node.get('name') or '')

        members.sort(key=sort_key)

        row_width = len(members) * X_GAP
        offset = X_START + max((canvas_width - row_width) / 2, 0)
        y = Y_START + layer_idx * Y_GAP

        current_layer_x = {}
        for i, node in enumerate(members):
            x = offset + i * X_GAP
            positions[node['id']] = (round(x, 1), round(y, 1))
            current_layer_x[node['id']] = x
        prev_layer_x = current_layer_x

    return positions
