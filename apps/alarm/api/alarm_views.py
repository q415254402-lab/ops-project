"""
告警管理 API
"""
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from django.db.models import Count, Q
from django.utils import timezone

from apps.alarm.models import Alarm, AlarmDefinition, AlarmHistory
from apps.alarm.serializers import (
    AlarmSerializer, AlarmListSerializer,
    AlarmDefinitionSerializer, AlarmHistorySerializer,
)


class AlarmViewSet(viewsets.ModelViewSet):
    """告警管理 ViewSet"""
    queryset = Alarm.objects.select_related('device', 'alarm_definition').all()
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['status', 'severity', 'device']
    search_fields = ['title', 'detail']
    ordering = ['-last_occurred_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return AlarmListSerializer
        return AlarmSerializer

    @action(detail=True, methods=['post'])
    def acknowledge(self, request, pk=None):
        """确认告警"""
        alarm = self.get_object()
        if alarm.status != 'active':
            return Response({'error': '只能确认活跃状态的告警'}, status=status.HTTP_400_BAD_REQUEST)
        alarm.status = 'acknowledged'
        alarm.acknowledged_by = request.user.username if request.user else 'system'
        alarm.acknowledged_at = timezone.now()
        alarm.save(update_fields=['status', 'acknowledged_by', 'acknowledged_at'])
        return Response({'message': '告警已确认'})

    @action(detail=True, methods=['post'])
    def clear(self, request, pk=None):
        """清除告警"""
        alarm = self.get_object()
        if alarm.status == 'cleared':
            return Response({'error': '告警已清除'}, status=status.HTTP_400_BAD_REQUEST)
        alarm.status = 'cleared'
        alarm.cleared_at = timezone.now()
        alarm.cleared_by = request.user.username if request.user else 'manual'
        alarm.save(update_fields=['status', 'cleared_at', 'cleared_by'])
        return Response({'message': '告警已清除'})

    @action(detail=False, methods=['post'])
    def batch_acknowledge(self, request):
        """批量确认"""
        ids = request.data.get('ids', [])
        Alarm.objects.filter(id__in=ids, status='active').update(
            status='acknowledged',
            acknowledged_by=request.user.username if request.user else 'system',
            acknowledged_at=timezone.now(),
        )
        return Response({'message': f'已确认 {len(ids)} 条告警'})

    @action(detail=False, methods=['post'])
    def batch_clear(self, request):
        """批量清除"""
        ids = request.data.get('ids', [])
        Alarm.objects.filter(id__in=ids).exclude(status='cleared').update(
            status='cleared',
            cleared_at=timezone.now(),
            cleared_by=request.user.username if request.user else 'manual',
        )
        return Response({'message': f'已清除 {len(ids)} 条告警'})

    @action(detail=False, methods=['get'])
    def statistics(self, request):
        """告警统计"""
        active_alarms = Alarm.objects.filter(status='active')
        stats = {
            'total_active': active_alarms.count(),
            'by_severity': dict(
                active_alarms.values_list('severity').annotate(c=Count('id')).values_list('severity', 'c')
            ),
            'by_device': list(
                active_alarms.values('device__name')
                .annotate(count=Count('id'))
                .order_by('-count')[:10]
            ),
            'recent_24h': Alarm.objects.filter(
                last_occurred_at__gte=timezone.now() - timezone.timedelta(hours=24)
            ).count(),
        }
        return Response(stats)

    @action(detail=False, methods=['get'])
    def trend(self, request):
        """告警趋势（按天统计）"""
        from django.db.models.functions import TruncDate
        days = int(request.query_params.get('days', 7))
        start = timezone.now() - timezone.timedelta(days=days)
        trend = (
            Alarm.objects.filter(first_occurred_at__gte=start)
            .annotate(date=TruncDate('first_occurred_at'))
            .values('date', 'severity')
            .annotate(count=Count('id'))
            .order_by('date')
        )
        return Response(list(trend))


class AlarmDefinitionViewSet(viewsets.ModelViewSet):
    queryset = AlarmDefinition.objects.all()
    serializer_class = AlarmDefinitionSerializer
    search_fields = ['name', 'code']
    filterset_fields = ['severity', 'source', 'enabled']
