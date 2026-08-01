from rest_framework.views import APIView
from rest_framework.response import Response
from django.db.models import Count
from django.db.models.functions import TruncDay
from django.utils import timezone
from datetime import timedelta

SEVERITY_ORDER = ['critical', 'major', 'minor']


class DashboardOverviewView(APIView):
    """Dashboard 总览 API"""
    def get(self, request):
        from apps.cmdb.models import Device
        from apps.alarm.models import Alarm

        now = timezone.now()
        devices = Device.objects.all()
        alarms = Alarm.objects.filter(status='active')

        # 设备统计
        total = devices.count()
        by_status = dict(devices.values_list('status').annotate(c=Count('id')).values_list('status', 'c'))
        by_type = list(devices.values('device_type__name').annotate(count=Count('id')).order_by('-count'))
        by_manufacturer = list(devices.values('manufacturer__name').annotate(count=Count('id')).order_by('-count'))

        # 告警统计
        alarm_by_severity = dict(alarms.values_list('severity').annotate(c=Count('id')).values_list('severity', 'c'))
        recent_alarms = Alarm.objects.filter(
            first_occurred_at__gte=now - timedelta(hours=24)
        ).values('severity').annotate(count=Count('id'))

        # 近 7 天告警趋势（按天、按等级）
        days = [(now - timedelta(days=i)).date() for i in range(6, -1, -1)]
        day_set = set(days)
        trend_qs = (
            Alarm.objects
            .filter(first_occurred_at__gte=now - timedelta(days=7))
            .annotate(day=TruncDay('first_occurred_at'))
            .values('day', 'severity')
            .annotate(count=Count('id'))
            .order_by('day', 'severity')
        )
        trend_map = {}
        for item in trend_qs:
            d = item['day'].date()
            if d in day_set:
                trend_map.setdefault(d, {})[item['severity']] = item['count']
        series = {sev: [trend_map.get(d, {}).get(sev, 0) for d in days] for sev in SEVERITY_ORDER}

        return Response({
            'device': {
                'total': total,
                'online': by_status.get('online', 0),
                'offline': by_status.get('offline', 0),
                'maintenance': by_status.get('maintenance', 0),
                'by_type': by_type,
                'by_manufacturer': by_manufacturer,
            },
            'alarm': {
                'total_active': alarms.count(),
                'by_severity': alarm_by_severity,
                'recent_24h': list(recent_alarms),
                'critical': alarm_by_severity.get('critical', 0),
            },
            'alarm_trend': {
                'labels': [d.strftime('%m-%d') for d in days],
                'series': series,
            },
        })


class HealthCheckView(APIView):
    """系统健康检查"""
    authentication_classes = []
    permission_classes = []

    def get(self, request):
        return Response({'status': 'healthy', 'timestamp': timezone.now().isoformat()})
