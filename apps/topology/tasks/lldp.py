# -*- coding: utf-8 -*-
"""
LLDP 拓扑自动发现

流程：
    1. collect_lldp_neighbors  —— 逐台 SNMP 采集 LLDP 邻居，写回 Interface
    2. build_physical_topology —— 邻居配对 → 去重成边 → 分层 → 布局 → 落库
    3. refresh_topology_status —— 刷新链路状态与带宽利用率（不重建拓扑）
"""
import logging
import re
from collections import defaultdict

from celery import shared_task
from django.db import transaction
from django.utils import timezone

from apps.topology.tasks.layout import assign_layers, compute_positions

logger = logging.getLogger('esight.topology')

DEFAULT_MAP_NAME = '物理拓扑（自动发现）'

# 层级 → 节点图标
LAYER_ICON = {
    'border': 'md-globe',
    'core': 'md-git-network',
    'aggregation': 'md-git-network',
    'access': 'md-git-network',
    'endpoint': 'md-desktop',
}


# ------------------------------------------------------------------ 采集
@shared_task(bind=True, max_retries=2, default_retry_delay=30)
def collect_lldp_neighbors(self, device_id):
    """采集单台设备的 LLDP 邻居并写回接口"""
    from apps.cmdb.models import Device
    from collectors.snmp_collector import SNMPCollector

    device = Device.objects.select_related('credential').get(id=device_id)
    if not device.credential or not device.credential.protocol.startswith('snmp'):
        logger.debug('设备 %s 无 SNMP 凭据，跳过 LLDP 采集', device.name)
        return 0

    try:
        with SNMPCollector(device.ip_address, device.credential, timeout=5, retries=1) as collector:
            neighbors = collector.get_lldp_neighbors() or []
    except Exception as exc:
        logger.warning('LLDP 采集失败 %s: %s', device.name, exc)
        return 0

    if not neighbors:
        return 0

    interfaces = {i.name: i for i in device.interfaces.all()}
    # 索引兜底：部分设备 localPortNum 即 ifIndex
    by_index = {i.index: i for i in interfaces.values() if i.index}

    saved = 0
    for nb in neighbors:
        iface = interfaces.get(nb.get('local_port')) or by_index.get(nb.get('local_port_num'))
        if iface is None:
            continue
        iface.lldp_remote_device = (nb.get('remote_system') or nb.get('remote_chassis') or '')[:128]
        iface.lldp_remote_port = (nb.get('remote_port') or '')[:128]
        iface.last_sync_at = timezone.now()
        iface.save(update_fields=['lldp_remote_device', 'lldp_remote_port', 'last_sync_at'])
        saved += 1

    logger.info('设备 %s 采集到 %s 条 LLDP 邻居', device.name, saved)
    return saved


@shared_task
def collect_all_lldp():
    """批量触发所有在线网络设备的 LLDP 采集"""
    from apps.cmdb.models import Device

    devices = Device.objects.filter(
        status='online',
        credential__isnull=False,
        device_type__code__in=['switch', 'router', 'firewall', 'wlc'],
    )
    for device in devices:
        collect_lldp_neighbors.delay(device.id)
    count = devices.count()
    logger.info('已触发 %s 台设备的 LLDP 采集', count)
    return count


# ------------------------------------------------------------------ 邻居匹配
def _norm_name(value):
    """归一化设备名：小写、去域名后缀、去空白"""
    if not value:
        return ''
    name = str(value).strip().lower()
    name = name.split('.')[0] if '.' in name and not _looks_like_ip(name) else name
    return name


def _looks_like_ip(value):
    return bool(re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', str(value or '').strip()))


def _norm_mac(value):
    """归一化 MAC：只保留 12 位十六进制小写"""
    if not value:
        return ''
    hexs = re.sub(r'[^0-9a-fA-F]', '', str(value)).lower()
    return hexs if len(hexs) == 12 else ''


def build_device_index(devices):
    """构造设备查找索引：名称 / MAC / IP"""
    by_name, by_mac, by_ip = {}, {}, {}
    for device in devices:
        for raw in (device.name, device.hostname):
            key = _norm_name(raw)
            if key:
                by_name.setdefault(key, device)
        by_ip[str(device.ip_address)] = device

        mac = _norm_mac(device.mac_address)
        if mac:
            by_mac.setdefault(mac, device)
        for iface in device.interfaces.all():
            imac = _norm_mac(iface.mac_address)
            if imac:
                by_mac.setdefault(imac, device)
    return by_name, by_mac, by_ip


def resolve_remote_device(remote_value, index):
    """
    把 LLDP 远端标识解析成本地 Device。

    remote_value 可能是设备名、chassis MAC，也可能是管理 IP。
    """
    by_name, by_mac, by_ip = index
    if not remote_value:
        return None

    raw = str(remote_value).strip()

    # 1) MAC
    mac = _norm_mac(raw)
    if mac and mac in by_mac:
        return by_mac[mac]

    # 2) IP
    if _looks_like_ip(raw) and raw in by_ip:
        return by_ip[raw]

    # 3) 设备名（含去域名后缀）
    name = _norm_name(raw)
    if name in by_name:
        return by_name[name]

    # 4) 名称中嵌了 IP
    ip_match = re.search(r'\d{1,3}(?:\.\d{1,3}){3}', raw)
    if ip_match and ip_match.group(0) in by_ip:
        return by_ip[ip_match.group(0)]

    return None


def collect_lldp_edges(devices, index):
    """
    从接口上的 LLDP 信息提取去重后的链路。

    :return: (edges, unresolved)
        edges: [{'a_device','a_iface','b_device','b_iface'}]  (device 为对象)
        unresolved: [{'device','local_port','remote'}]
    """
    edges = {}
    unresolved = []

    for device in devices:
        for iface in device.interfaces.all():
            remote = (iface.lldp_remote_device or '').strip()
            if not remote:
                continue

            peer = resolve_remote_device(remote, index)
            if peer is None:
                unresolved.append({
                    'device': device.name,
                    'local_port': iface.name,
                    'remote': remote,
                    'remote_port': iface.lldp_remote_port,
                })
                continue
            if peer.id == device.id:
                continue  # 自环（同设备两口对插）忽略

            peer_iface = _match_peer_interface(peer, iface.lldp_remote_port)

            # 无向去重：以 (设备ID, 接口名) 二元组排序作 key
            side_a = (device.id, iface.name)
            side_b = (peer.id, peer_iface.name if peer_iface else (iface.lldp_remote_port or ''))
            key = tuple(sorted([side_a, side_b]))
            if key in edges:
                continue

            edges[key] = {
                'a_device': device, 'a_iface': iface,
                'b_device': peer, 'b_iface': peer_iface,
            }

    return list(edges.values()), unresolved


def _match_peer_interface(peer, remote_port):
    """在对端设备上找到 LLDP 报文里提到的接口"""
    if not remote_port:
        return None
    target = str(remote_port).strip().lower()
    candidates = list(peer.interfaces.all())

    for iface in candidates:              # 精确匹配
        if iface.name.lower() == target:
            return iface
    for iface in candidates:              # 描述匹配
        if iface.description and iface.description.lower() == target:
            return iface
    for iface in candidates:              # 编号匹配 GE0/0/1 ←→ GigabitEthernet0/0/1
        suffix = re.search(r'[\d/:.]+$', iface.name)
        target_suffix = re.search(r'[\d/:.]+$', target)
        if suffix and target_suffix and suffix.group(0) == target_suffix.group(0):
            return iface
    return None


# ------------------------------------------------------------------ 构建拓扑
@shared_task
def build_physical_topology(map_id=None, name=DEFAULT_MAP_NAME, include_isolated=False):
    """
    根据 LLDP 邻居关系重建物理拓扑。

    :param map_id:           指定重建的拓扑图；None 则按 name 复用或新建
    :param include_isolated: 是否把没有任何链路的设备也画进来
    """
    from apps.cmdb.models import Device
    from apps.topology.models import TopologyLink, TopologyMap, TopologyNode

    devices = list(
        Device.objects.exclude(status='decommissioned')
        .select_related('device_type')
        .prefetch_related('interfaces')
    )
    if not devices:
        return {'nodes': 0, 'links': 0, 'message': 'CMDB 中暂无设备'}

    index = build_device_index(devices)
    edges, unresolved = collect_lldp_edges(devices, index)

    # 参与成图的设备
    linked_ids = set()
    for edge in edges:
        linked_ids.add(edge['a_device'].id)
        linked_ids.add(edge['b_device'].id)

    if include_isolated:
        members = devices
    else:
        members = [d for d in devices if d.id in linked_ids]

    if not members:
        return {
            'nodes': 0, 'links': 0,
            'unresolved': len(unresolved),
            'message': '未发现任何 LLDP 邻居关系，请先执行 LLDP 采集，或勾选“包含孤立设备”',
        }

    # 分层 + 布局
    layout_nodes = [{
        'id': d.id,
        'name': d.name or d.hostname or str(d.ip_address),
        'type_code': (d.device_type.code if d.device_type else 'unknown'),
    } for d in members]
    layout_edges = [(e['a_device'].id, e['b_device'].id) for e in edges]

    layers = assign_layers(layout_nodes, layout_edges)
    positions = compute_positions(layout_nodes, layers, layout_edges)

    with transaction.atomic():
        if map_id:
            topo_map = TopologyMap.objects.get(id=map_id)
        else:
            topo_map, _ = TopologyMap.objects.get_or_create(
                name=name,
                map_type='physical',
                defaults={'description': '由 LLDP 邻居关系自动生成', 'is_default': True},
            )

        # 全量重建（节点删除会级联删除链路）
        TopologyNode.objects.filter(topology_map=topo_map).delete()

        node_by_device = {}
        for device in members:
            x, y = positions.get(device.id, (0, 0))
            layer = layers.get(device.id, 'endpoint')
            node_by_device[device.id] = TopologyNode.objects.create(
                topology_map=topo_map,
                device=device,
                label=device.name or device.hostname or str(device.ip_address),
                x=x, y=y,
                layer=layer,
                icon=LAYER_ICON.get(layer, 'md-cube'),
            )

        link_objs = []
        for edge in edges:
            src = node_by_device.get(edge['a_device'].id)
            dst = node_by_device.get(edge['b_device'].id)
            if not src or not dst:
                continue
            a_iface, b_iface = edge['a_iface'], edge['b_iface']
            link_objs.append(TopologyLink(
                topology_map=topo_map,
                source_node=src, source_interface=a_iface,
                target_node=dst, target_interface=b_iface,
                link_type='physical',
                bandwidth=_link_bandwidth(a_iface, b_iface),
                status=_link_status(a_iface, b_iface),
            ))
        TopologyLink.objects.bulk_create(link_objs)

        topo_map.layout_config = {
            'algorithm': 'lldp-hierarchical',
            'layers': _count_by_layer(layers),
            'unresolved': unresolved[:50],
            'generated_at': timezone.now().isoformat(),
        }
        topo_map.save(update_fields=['layout_config', 'updated_at'])

    logger.info(
        '拓扑构建完成 map=%s 节点=%s 链路=%s 未匹配邻居=%s',
        topo_map.id, len(members), len(link_objs), len(unresolved),
    )
    return {
        'map_id': topo_map.id,
        'map_name': topo_map.name,
        'nodes': len(members),
        'links': len(link_objs),
        'unresolved': len(unresolved),
        'layers': _count_by_layer(layers),
    }


def _count_by_layer(layers):
    counter = defaultdict(int)
    for layer in layers.values():
        counter[layer] += 1
    return dict(counter)


def _link_bandwidth(a_iface, b_iface):
    """链路带宽取两端接口速率的较小值"""
    speeds = [i.speed for i in (a_iface, b_iface) if i is not None and i.speed]
    return min(speeds) if speeds else 0


def _link_status(a_iface, b_iface):
    """任一端 down 即判定链路 down"""
    statuses = [i.status for i in (a_iface, b_iface) if i is not None]
    if not statuses:
        return 'unknown'
    return 'down' if any(s == 'down' for s in statuses) else 'up'


# ------------------------------------------------------------------ 状态刷新
@shared_task
def refresh_topology_status(map_id=None):
    """刷新链路状态与带宽利用率（不重建结构，适合高频调度）"""
    from apps.performance.models import InterfaceTraffic
    from apps.topology.models import TopologyLink, TopologyMap

    maps = TopologyMap.objects.filter(id=map_id) if map_id else TopologyMap.objects.all()
    updated = 0

    for topo_map in maps:
        links = TopologyLink.objects.filter(topology_map=topo_map).select_related(
            'source_interface', 'target_interface',
        )
        for link in links:
            a_iface, b_iface = link.source_interface, link.target_interface
            new_status = _link_status(a_iface, b_iface)
            new_util = _latest_utilization(InterfaceTraffic, a_iface, b_iface)

            if new_status != link.status or abs(new_util - (link.utilization or 0)) > 0.1:
                link.status = new_status
                link.utilization = new_util
                link.save(update_fields=['status', 'utilization'])
                updated += 1

    logger.info('拓扑状态刷新完成，更新 %s 条链路', updated)
    return updated


def _latest_utilization(traffic_model, *interfaces):
    """取两端接口最新流量记录中的最大利用率"""
    values = []
    for iface in interfaces:
        if iface is None:
            continue
        latest = (
            traffic_model.objects.filter(interface=iface)
            .order_by('-timestamp')
            .values('in_utilization', 'out_utilization')
            .first()
        )
        if latest:
            values.append(max(latest['in_utilization'] or 0, latest['out_utilization'] or 0))
    return round(max(values), 2) if values else 0.0
