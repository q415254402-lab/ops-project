# -*- coding: utf-8 -*-
"""
拓扑管理 API
"""
import logging

from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from apps.topology.models import DiscoveryTask, TopologyLink, TopologyMap, TopologyNode
from apps.topology.serializers import (
    DiscoveryTaskSerializer, TopologyLinkSerializer,
    TopologyMapSerializer, TopologyNodeSerializer,
)

logger = logging.getLogger('esight.topology')

# 层级 → 画布顺序，供前端图例排序
LAYER_LABELS = [
    ('border', '出口层'),
    ('core', '核心层'),
    ('aggregation', '汇聚层'),
    ('access', '接入层'),
    ('endpoint', '终端层'),
]


class TopologyMapViewSet(viewsets.ModelViewSet):
    queryset = TopologyMap.objects.all()
    serializer_class = TopologyMapSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['map_type', 'is_default']
    search_fields = ['name']
    ordering = ['-is_default', 'name']

    @action(detail=True, methods=['get'])
    def data(self, request, pk=None):
        """获取拓扑图完整数据（节点 + 连线）"""
        topo = self.get_object()
        nodes = TopologyNode.objects.filter(topology_map=topo).select_related(
            'device', 'device__device_type',
        )
        links = TopologyLink.objects.filter(topology_map=topo).select_related(
            'source_node', 'target_node', 'source_interface', 'target_interface',
        )

        # 各设备活跃告警数，用于节点角标
        from apps.alarm.models import Alarm
        device_ids = [n.device_id for n in nodes if n.device_id]
        alarm_counts = {}
        if device_ids:
            from django.db.models import Count
            alarm_counts = dict(
                Alarm.objects.filter(device_id__in=device_ids, status='active')
                .values_list('device_id')
                .annotate(c=Count('id'))
                .values_list('device_id', 'c')
            )

        graph = {
            'map': {
                'id': topo.id,
                'name': topo.name,
                'type': topo.map_type,
                'layout': topo.layout_config or {},
                'updated_at': topo.updated_at,
            },
            'layers': [
                {'code': code, 'label': label}
                for code, label in LAYER_LABELS
                if any(n.layer == code for n in nodes)
            ],
            'nodes': [{
                'id': str(n.id),
                'label': n.label or (n.device.name if n.device else ''),
                'x': n.x, 'y': n.y, 'layer': n.layer,
                'deviceId': n.device_id,
                'deviceName': n.device.name if n.device else '',
                'deviceIp': str(n.device.ip_address) if n.device else '',
                'deviceType': n.device.device_type.code if (n.device and n.device.device_type) else '',
                'deviceTypeName': n.device.device_type.name if (n.device and n.device.device_type) else '',
                'status': n.device.status if n.device else 'unknown',
                'icon': n.icon,
                'alarmCount': alarm_counts.get(n.device_id, 0),
            } for n in nodes],
            'edges': [{
                'id': str(l.id),
                'source': str(l.source_node_id),
                'target': str(l.target_node_id),
                'sourcePort': l.source_interface.name if l.source_interface else '',
                'targetPort': l.target_interface.name if l.target_interface else '',
                'bandwidth': l.bandwidth,
                'utilization': l.utilization,
                'status': l.status,
                'linkType': l.link_type,
            } for l in links],
        }
        return Response(graph)

    @action(detail=False, methods=['post'])
    def build(self, request):
        """
        基于 LLDP 邻居关系自动构建物理拓扑

        body: {"name": "物理拓扑", "include_isolated": false, "async": false}
        """
        from apps.topology.tasks.lldp import build_physical_topology

        name = request.data.get('name') or '物理拓扑（自动发现）'
        include_isolated = bool(request.data.get('include_isolated'))
        map_id = request.data.get('map_id') or None

        if request.data.get('async'):
            from apps.discovery.api.discovery_views import dispatch_task
            mode = dispatch_task(build_physical_topology, map_id, name, include_isolated)
            return Response({'message': '拓扑构建任务已提交', 'mode': mode})

        try:
            result = build_physical_topology(map_id, name, include_isolated)
        except Exception as exc:
            logger.exception('拓扑构建失败')
            return Response(
                {'detail': f'构建失败: {exc}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        return Response(result)

    @action(detail=True, methods=['post'])
    def refresh(self, request, pk=None):
        """刷新链路状态与利用率"""
        from apps.topology.tasks.lldp import refresh_topology_status

        topo = self.get_object()
        updated = refresh_topology_status(topo.id)
        return Response({'message': f'已刷新 {updated} 条链路', 'updated': updated})

    @action(detail=False, methods=['post'], url_path='collect-lldp')
    def collect_lldp(self, request):
        """触发全网 LLDP 采集（为下一次构建准备数据）"""
        from apps.discovery.api.discovery_views import dispatch_task
        from apps.topology.tasks.lldp import collect_all_lldp

        mode = dispatch_task(collect_all_lldp)
        return Response({'message': '已触发 LLDP 采集', 'mode': mode})

    @action(detail=True, methods=['get', 'put', 'patch'],
            url_path=r'nodes/(?P<node_id>[^/.]+)')
    def node_detail(self, request, pk=None, node_id=None):
        """读取 / 更新单个拓扑节点（前端拖拽后保存坐标）"""
        topo = self.get_object()
        try:
            node = TopologyNode.objects.get(id=node_id, topology_map=topo)
        except TopologyNode.DoesNotExist:
            return Response({'detail': '节点不存在'}, status=status.HTTP_404_NOT_FOUND)

        if request.method == 'GET':
            return Response(TopologyNodeSerializer(node).data)

        serializer = TopologyNodeSerializer(node, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

    @action(detail=True, methods=['post'], url_path='save-layout')
    def save_layout(self, request, pk=None):
        """
        批量保存节点坐标

        body: {"nodes": [{"id": 1, "x": 100, "y": 200}, ...]}
        """
        topo = self.get_object()
        items = request.data.get('nodes') or []
        if not isinstance(items, list):
            return Response({'detail': 'nodes 必须是数组'}, status=status.HTTP_400_BAD_REQUEST)

        node_map = {n.id: n for n in TopologyNode.objects.filter(topology_map=topo)}
        to_update = []
        for item in items:
            try:
                node = node_map.get(int(item.get('id')))
            except (TypeError, ValueError):
                continue
            if node is None:
                continue
            node.x = float(item.get('x', node.x))
            node.y = float(item.get('y', node.y))
            to_update.append(node)

        if to_update:
            TopologyNode.objects.bulk_update(to_update, ['x', 'y'])
        return Response({'updated': len(to_update)})

    @action(detail=True, methods=['get'])
    def links(self, request, pk=None):
        """链路明细（含利用率排序，便于定位拥塞）"""
        topo = self.get_object()
        qs = TopologyLink.objects.filter(topology_map=topo).select_related(
            'source_node', 'target_node',
        ).order_by('-utilization')
        return Response(TopologyLinkSerializer(qs, many=True).data)


class DiscoveryTaskViewSet(viewsets.ModelViewSet):
    """
    发现任务（兼容旧路由 /api/v1/topology/discovery/）

    完整能力见 /api/v1/discovery/tasks/
    """
    queryset = DiscoveryTask.objects.all()
    serializer_class = DiscoveryTaskSerializer
    filterset_fields = ['status']
    ordering = ['-created_at']

    @action(detail=True, methods=['get'])
    def results(self, request, pk=None):
        task = self.get_object()
        return Response(task.result or {})

    @action(detail=True, methods=['post'])
    def run(self, request, pk=None):
        """执行发现任务"""
        from apps.discovery.api.discovery_views import dispatch_task
        from apps.discovery.tasks.scan import run_discovery_task

        task = self.get_object()
        if task.status == 'running':
            return Response({'detail': '任务正在执行中'}, status=status.HTTP_409_CONFLICT)
        mode = dispatch_task(run_discovery_task, task.id, bool(request.data.get('auto_import')))
        return Response({'message': '已提交发现任务', 'mode': mode})
