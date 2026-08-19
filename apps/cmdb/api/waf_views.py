# -*- coding: utf-8 -*-
"""
WAF 攻击日志 API（2026-08-17）
数据源：cmdb_waf_attack_log（syslog 接收器落库）
接口：
  GET /waf/logs/?start=&end=&src_ip=&dst_ip=&event_type=&severity=&dev_ip=&limit=&offset=
  GET /waf/stats/?range=24h|7d    统计卡 + 攻击类型分布 + 趋势 + TOP源IP
"""
import logging
from datetime import datetime, timedelta

from django.db.models import Count, Q
from django.http import JsonResponse
from django.utils import timezone
from rest_framework.views import APIView
from rest_framework.authentication import SessionAuthentication

from apps.cmdb.models import WafAttackLog

logger = logging.getLogger('app')


class CSRFExemptSessionAuthentication(SessionAuthentication):
    def enforce_csrf(self, request):
        return


def _ok(data=None, msg='信息获取成功'):
    if data is None:
        data = {}
    return JsonResponse({'code': 200, 'successcode': 20005, 'message': msg, 'data': data})


def _err(msg):
    return JsonResponse({'code': 400, 'successcode': 40001, 'message': msg, 'data': None})


def _parse_dt(s, default_delta=None):
    if not s:
        return timezone.now() - default_delta if default_delta else None
    try:
        return datetime.strptime(str(s), '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.get_current_timezone())
    except ValueError:
        try:
            return datetime.fromtimestamp(int(s)).replace(tzinfo=timezone.get_current_timezone())
        except Exception:
            return None


class WafLogsView(APIView):
    """WAF 攻击日志列表（分页 + 过滤）"""
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        qs = WafAttackLog.objects.all()
        start = _parse_dt(request.GET.get('start'), timedelta(days=1))
        end = _parse_dt(request.GET.get('end'))
        if start:
            qs = qs.filter(log_time__gte=start)
        if end:
            qs = qs.filter(log_time__lte=end)
        for f in ('src_ip', 'dst_ip', 'event_type', 'dev_ip'):
            v = request.GET.get(f)
            if v:
                qs = qs.filter(**{f + '__icontains': v})
        # 2026-08-17：severity 过滤（支持中英文：high→高/严重/high，medium→中，low→低）
        sev = request.GET.get('severity')
        if sev:
            _sev_map = {
                'high': ['高', '严重', 'high', 'High', 'HIGH', 'Critical', 'crit'],
                'medium': ['中', 'medium', 'Medium'],
                'low': ['低', 'low', 'Low'],
            }
            targets = _sev_map.get(sev.lower(), [sev])
            qs = qs.filter(severity__in=targets)
        # 2026-08-17：device_type 过滤（WAF / Firewall）
        dt = request.GET.get('device_type')
        if dt:
            qs = qs.filter(device_type=dt)
        total = qs.count()
        limit = min(int(request.GET.get('limit') or 50), 500)
        offset = int(request.GET.get('offset') or 0)
        rows = list(qs.values(
            'id', 'log_time', 'dev_ip', 'src_ip', 'src_port', 'dst_ip', 'dst_port',
            'event_type', 'severity', 'action', 'msg', 'rule_id', 'method', 'domain', 'uri',
        )[offset:offset + limit])
        for r in rows:
            # 2026-08-17：输出转本地时区（TIME_ZONE=Asia/Shanghai，数据库存 UTC）
            r['log_time'] = timezone.localtime(r['log_time']).strftime('%Y-%m-%d %H:%M:%S') if r['log_time'] else ''
        return _ok({'total': total, 'data': rows})


class WafStatsView(APIView):
    """WAF 攻击统计（统计卡 + 类型分布 + 趋势 + TOP源IP）"""
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        rng = request.GET.get('range', '24h')
        hours = 24 if rng == '24h' else 7 * 24
        since = timezone.now() - timedelta(hours=hours)
        qs = WafAttackLog.objects.filter(log_time__gte=since)
        dt = request.GET.get('device_type')
        if dt:
            qs = qs.filter(device_type=dt)

        total = qs.count()
        high_cnt = qs.filter(severity__in=['高', 'high', '严重', 'HIGH', 'Critical', 'crit']).count()

        # 2026-08-17：src/dst 分组增加高危次数 high + 最近时间 last（供统计卡下钻列表）；全量（不截断 10）
        def _enrich_ip(ip_key):
            out = []
            rows = qs.values(ip_key).exclude(**{ip_key: ''}).annotate(c=Count('id')).order_by('-c')[:500]
            for r in rows:
                ip = r[ip_key]
                high = qs.filter(**{ip_key: ip, 'severity__in': ['高', 'high', '严重', 'HIGH', 'Critical', 'crit']}).count()
                last = qs.filter(**{ip_key: ip}).order_by('-log_time').values_list('log_time', flat=True).first()
                out.append({
                    ip_key: ip, 'c': r['c'], 'high': high,
                    'last': timezone.localtime(last).strftime('%Y-%m-%d %H:%M') if last else '',
                })
            return out

        src_list = _enrich_ip('src_ip')
        dst_list = _enrich_ip('dst_ip')
        # 攻击类型分布
        types = qs.values('event_type').exclude(event_type='').annotate(c=Count('id')).order_by('-c')[:15]
        # 按小时趋势
        trend = {}
        for i in range(hours, -1, -1):
            t = since + timedelta(hours=hours - i)
            trend[t.strftime('%H:%M')] = 0
        for row in qs.values('log_time'):
            lt = timezone.localtime(row['log_time'])
            trend[lt.strftime('%H:%M')] = trend.get(lt.strftime('%H:%M'), 0) + 1
        # 最近 20 条
        recent = list(qs.values(
            'id', 'log_time', 'dev_ip', 'src_ip', 'dst_ip', 'event_type', 'severity', 'action', 'msg',
        ).order_by('-log_time')[:20])
        for r in recent:
            r['log_time'] = timezone.localtime(r['log_time']).strftime('%Y-%m-%d %H:%M:%S') if r['log_time'] else ''
        return _ok({
            'range_hours': hours,
            'total': total,
            'high_cnt': high_cnt,
            'src_ip_cnt': qs.values('src_ip').exclude(src_ip='').distinct().count(),
            'dst_ip_cnt': qs.values('dst_ip').exclude(dst_ip='').distinct().count(),
            'type_dist': list(types),
            'src_top': src_list,
            'dst_top': dst_list,
            'trend': trend,
            'recent': recent,
        })
