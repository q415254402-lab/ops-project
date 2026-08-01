"""
CMDB 设备管理 API
"""
from rest_framework import viewsets, status, filters
from rest_framework.decorators import action
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from django.db.models import Count, Q

from apps.cmdb.models import Device, DeviceType, DeviceModel, Manufacturer, Interface
from apps.cmdb.serializers import (
    DeviceListSerializer, DeviceDetailSerializer,
    DeviceCreateUpdateSerializer, DeviceTypeSerializer,
    DeviceModelSerializer, ManufacturerSerializer,
    InterfaceSerializer,
)
from apps.cmdb.tasks.sync import sync_device_info


class DeviceViewSet(viewsets.ModelViewSet):
    """设备管理 ViewSet"""
    queryset = Device.objects.all()
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'hostname', 'ip_address', 'serial_number']
    filterset_fields = ['status', 'device_type', 'manufacturer', 'manage_type', 'room']
    ordering_fields = ['name', 'ip_address', 'created_at', 'last_seen_at']
    ordering = ['-created_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return DeviceListSerializer
        elif self.action in ['create', 'update', 'partial_update']:
            return DeviceCreateUpdateSerializer
        return DeviceDetailSerializer

    @action(detail=True, methods=['post'])
    def sync(self, request, pk=None):
        """触发设备同步"""
        device = self.get_object()
        sync_device_info.delay(device.id)
        return Response({'message': f'已触发设备 {device.name} 的同步任务'})

    @action(detail=True, methods=['get'])
    def interfaces(self, request, pk=None):
        """获取设备接口列表"""
        device = self.get_object()
        interfaces = device.interfaces.all()
        serializer = InterfaceSerializer(interfaces, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def alarms(self, request, pk=None):
        """获取设备活跃告警"""
        device = self.get_object()
        from apps.alarm.models import Alarm
        from apps.alarm.serializers import AlarmSerializer
        alarms = Alarm.objects.filter(device=device, status='active').order_by('-severity')
        serializer = AlarmSerializer(alarms, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def statistics(self, request):
        """设备统计"""
        total = Device.objects.count()
        by_status = dict(Device.objects.values_list('status').annotate(c=Count('id')).values_list('status', 'c'))
        by_type = list(
            Device.objects.values('device_type__name')
            .annotate(count=Count('id'))
            .order_by('-count')
        )
        online_count = by_status.get('online', 0)
        offline_count = by_status.get('offline', 0)
        return Response({
            'total': total,
            'online': online_count,
            'offline': offline_count,
            'maintenance': by_status.get('maintenance', 0),
            'by_status': by_status,
            'by_type': by_type,
        })

    @action(detail=False, methods=['post'])
    def batch_import(self, request):
        """批量导入设备"""
        # TODO: 实现 Excel/CSV 批量导入
        return Response({'message': '批量导入功能开发中'}, status=status.HTTP_501_NOT_IMPLEMENTED)

    @action(detail=False, methods=['get'])
    def export(self, request):
        """导出设备列表"""
        # TODO: 实现 Excel 导出
        return Response({'message': '导出功能开发中'}, status=status.HTTP_501_NOT_IMPLEMENTED)


class DeviceTypeViewSet(viewsets.ModelViewSet):
    queryset = DeviceType.objects.all()
    serializer_class = DeviceTypeSerializer


class DeviceModelViewSet(viewsets.ModelViewSet):
    queryset = DeviceModel.objects.select_related('manufacturer', 'device_type').all()
    serializer_class = DeviceModelSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['manufacturer', 'device_type']


class ManufacturerViewSet(viewsets.ModelViewSet):
    queryset = Manufacturer.objects.all()
    serializer_class = ManufacturerSerializer
    search_fields = ['name', 'code']
