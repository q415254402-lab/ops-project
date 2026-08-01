# -*- coding: utf-8 -*-
"""
CMDB 资源管理 API —— 机房 / 机柜 / IP 地址 / VLAN / 凭据 / 接口
"""
import ipaddress

from django.db.models import Count
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from apps.cmdb.models import (
    Cabinet, Credential, Interface, IPAddress, Room, Vlan,
)
from apps.cmdb.serializers import (
    CabinetSerializer, CredentialSerializer, InterfaceSerializer,
    IPAddressSerializer, RoomSerializer, VlanSerializer,
)


class RoomViewSet(viewsets.ModelViewSet):
    """机房管理"""
    queryset = Room.objects.all()
    serializer_class = RoomSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'code', 'area', 'address']
    ordering = ['name']

    @action(detail=True, methods=['get'])
    def cabinets(self, request, pk=None):
        """机房下的机柜列表"""
        room = self.get_object()
        serializer = CabinetSerializer(room.cabinets.all(), many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def devices(self, request, pk=None):
        """机房下的设备列表"""
        from apps.cmdb.serializers import DeviceListSerializer
        room = self.get_object()
        serializer = DeviceListSerializer(room.devices.all(), many=True)
        return Response(serializer.data)


class CabinetViewSet(viewsets.ModelViewSet):
    """机柜管理"""
    queryset = Cabinet.objects.select_related('room').all()
    serializer_class = CabinetSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ['room']
    search_fields = ['name']


class VlanViewSet(viewsets.ModelViewSet):
    """VLAN 管理"""
    queryset = Vlan.objects.all()
    serializer_class = VlanSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    search_fields = ['name', 'vlan_id']


class IPAddressViewSet(viewsets.ModelViewSet):
    """IP 地址管理"""
    queryset = IPAddress.objects.select_related('device', 'vlan').all()
    serializer_class = IPAddressSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['status', 'subnet', 'vlan', 'device']
    search_fields = ['address', 'hostname', 'description']
    ordering = ['address']

    @action(detail=False, methods=['get'])
    def statistics(self, request):
        """IP 使用统计（可按 subnet 过滤）"""
        qs = self.filter_queryset(self.get_queryset())
        by_status = dict(
            qs.values_list('status').annotate(c=Count('id')).values_list('status', 'c')
        )
        total = qs.count()
        allocated = by_status.get('allocated', 0)
        return Response({
            'total': total,
            'allocated': allocated,
            'available': by_status.get('available', 0),
            'reserved': by_status.get('reserved', 0),
            'conflict': by_status.get('conflict', 0),
            'usage_percent': round(allocated * 100.0 / total, 1) if total else 0,
            'by_status': by_status,
        })

    @action(detail=False, methods=['get'])
    def subnets(self, request):
        """已登记的网段汇总"""
        rows = (
            self.get_queryset().values('subnet')
            .annotate(total=Count('id'))
            .order_by('subnet')
        )
        return Response(list(rows))

    @action(detail=False, methods=['post'])
    def generate(self, request):
        """
        按网段批量生成 IP 台账

        body: {"subnet": "192.168.1.0/24", "gateway": "192.168.1.1", "vlan": 10}
        """
        subnet = request.data.get('subnet')
        if not subnet:
            return Response({'detail': '缺少 subnet 参数'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            network = ipaddress.ip_network(subnet, strict=False)
        except ValueError as exc:
            return Response({'detail': f'网段格式不合法: {exc}'}, status=status.HTTP_400_BAD_REQUEST)

        if network.num_addresses > 4096:
            return Response(
                {'detail': '单次最多生成 4096 个地址，请拆分网段'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        gateway = request.data.get('gateway') or None
        vlan_id = request.data.get('vlan') or None

        created = 0
        exists = set(
            IPAddress.objects.filter(subnet=str(network)).values_list('address', flat=True)
        )
        bulk = []
        for ip in network.hosts():
            addr = str(ip)
            if addr in exists:
                continue
            bulk.append(IPAddress(
                address=addr,
                subnet=str(network),
                gateway=gateway,
                vlan_id=vlan_id,
                status='available',
            ))
            created += 1
        if bulk:
            IPAddress.objects.bulk_create(bulk, ignore_conflicts=True)

        return Response({'subnet': str(network), 'created': created, 'skipped': len(exists)})


class CredentialViewSet(viewsets.ModelViewSet):
    """采集凭据管理（密码只写不读）"""
    queryset = Credential.objects.all()
    serializer_class = CredentialSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ['protocol']
    search_fields = ['name', 'username']

    @action(detail=True, methods=['post'])
    def test(self, request, pk=None):
        """连通性测试：对指定 IP 用该凭据尝试采集"""
        credential = self.get_object()
        ip = request.data.get('ip_address')
        if not ip:
            return Response({'detail': '缺少 ip_address 参数'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            if credential.protocol.startswith('snmp'):
                from collectors.snmp_collector import SNMPCollector
                with SNMPCollector(ip, credential, timeout=5, retries=1) as collector:
                    info = collector.get_system_info()
                ok = bool(info)
                return Response({'success': ok, 'info': info or {}})

            if credential.protocol == 'ssh':
                from collectors.ssh_collector import SSHCollector
                with SSHCollector(ip, credential, timeout=8) as collector:
                    info = collector.get_system_info()
                return Response({'success': bool(info), 'info': info or {}})

            return Response(
                {'success': False, 'detail': f'暂不支持 {credential.protocol} 协议的连通性测试'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as exc:
            return Response({'success': False, 'detail': str(exc)[:300]})


class InterfaceViewSet(viewsets.ReadOnlyModelViewSet):
    """接口查询（只读，写入由采集器负责）"""
    queryset = Interface.objects.select_related('device').all()
    serializer_class = InterfaceSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ['device', 'status', 'if_type']
    search_fields = ['name', 'description']
