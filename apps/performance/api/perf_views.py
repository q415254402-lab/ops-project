from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from django.utils import timezone
from django.db.models import Avg, Max, Min
from datetime import timedelta
from apps.performance.models import MetricDefinition, CollectTask, MetricThreshold, MetricData, InterfaceTraffic
from apps.performance.serializers import (
    MetricDefinitionSerializer, CollectTaskSerializer,
    MetricThresholdSerializer, MetricDataSerializer,
)

class MetricDefinitionViewSet(viewsets.ModelViewSet):
    queryset = MetricDefinition.objects.select_related('device_type').all()
    serializer_class = MetricDefinitionSerializer
    filterset_fields = ['device_type', 'collection_method', 'enabled']

class CollectTaskViewSet(viewsets.ModelViewSet):
    queryset = CollectTask.objects.all()
    serializer_class = CollectTaskSerializer
    filterset_fields = ['status', 'enabled']

class MetricThresholdViewSet(viewsets.ModelViewSet):
    queryset = MetricThreshold.objects.select_related('metric', 'device').all()
    serializer_class = MetricThresholdSerializer
    filterset_fields = ['metric', 'device', 'level']

class MetricDataViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = MetricData.objects.select_related('device', 'metric').all()
    serializer_class = MetricDataSerializer
    filterset_fields = ['device', 'metric']

    def get_queryset(self):
        qs = super().get_queryset()
        start = self.request.query_params.get('start')
        end = self.request.query_params.get('end')
        if start:
            qs = qs.filter(timestamp__gte=start)
        if end:
            qs = qs.filter(timestamp__lte=end)
        return qs.order_by('-timestamp')[:1000]

    @action(detail=False, methods=['get'])
    def summary(self, request):
        """指标汇总（最近1小时/24小时/7天的 avg/max/min）"""
        device_id = request.query_params.get('device_id')
        metric_code = request.query_params.get('metric_code')
        hours = int(request.query_params.get('hours', 1))
        if not device_id or not metric_code:
            return Response({'error': '需要 device_id 和 metric_code'}, status=400)
        metric = MetricDefinition.objects.filter(code=metric_code).first()
        if not metric:
            return Response({'error': f'指标 {metric_code} 不存在'}, status=404)
        since = timezone.now() - timedelta(hours=hours)
        data = MetricData.objects.filter(
            device_id=device_id, metric=metric, timestamp__gte=since
        ).aggregate(avg=Avg('value'), max=Max('value'), min=Min('value'))
        return Response({
            'device_id': device_id,
            'metric': metric_code,
            'hours': hours,
            'avg': round(data['avg'] or 0, 2),
            'max': round(data['max'] or 0, 2),
            'min': round(data['min'] or 0, 2),
        })
