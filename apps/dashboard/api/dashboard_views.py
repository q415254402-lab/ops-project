from rest_framework.views import APIView
from rest_framework.response import Response
from django.db.models import Count
from django.db.models.functions import TruncDay
from django.utils import timezone
from datetime import timedelta

SEVERITY_ORDER = ['critical', 'major', 'minor']


class DashboardOverviewView(APIView):
    """Dashboard 总览 API

    数据源策略（用户拍板：完全复刻 control + 薄代理调平台，少维护一套数据）：
    - 设备统计 → 从管控平台(control)读（network-equipment-all），不读 eSight 本地设备表
    - 告警统计/趋势 → eSight 本地（control 没有告警，属 eSight 增量能力）
    """

    def get(self, request):
        from apps.alarm.models import Alarm
        from apps.cmdb.services import platform_proxy

        now = timezone.now()
        alarms = Alarm.objects.filter(status='active')

        # ── 设备统计：薄代理读平台 ──
        device_total = 0
        device_by_type = []
        device_brands = []
        device_snmp_ok = 0
        try:
            plat = platform_proxy.get_network_equipments(request=request) or []
            device_total = len(plat)
            type_counter = {}
            brand_counter = {}
            for d in plat:
                et = (d.get('equipment_type') or {}).get('name') or (d.get('equipment_type') or {}).get('code') or '未知'
                type_counter[et] = type_counter.get(et, 0) + 1
                brand = d.get('device_type') or '未知'
                brand_counter[brand] = brand_counter.get(brand, 0) + 1
                if d.get('snmp_state') == 'normal':
                    device_snmp_ok += 1
            device_by_type = [{'device_type__name': k, 'count': v} for k, v in sorted(type_counter.items(), key=lambda x: -x[1])]
            device_brands = [{'manufacturer__name': k, 'count': v} for k, v in sorted(brand_counter.items(), key=lambda x: -x[1])]
        except Exception as exc:  # noqa: BLE001 —— 平台不可用时设备统计为 0，不阻塞 Dashboard
            import logging
            logging.getLogger('app').warning('[dashboard] 平台设备统计失败: %s', exc)

        # ── 告警统计（eSight 本地） ──
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
                'total': device_total,
                'online': device_snmp_ok,
                'offline': max(0, device_total - device_snmp_ok),
                'maintenance': 0,
                'by_type': device_by_type,
                'by_manufacturer': device_brands,
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
