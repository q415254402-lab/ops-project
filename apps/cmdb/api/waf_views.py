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

from django.db.models import Count, Q, Max
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


def _resolve_window(request, default_hours=24, default_range='24h'):
    """统一解析时间窗（统计卡 WafStatsView 与列表 WafLogsView 共用）。
    返回 (since, until, rng, is_custom)：
      · range=24h|3d|7d → 固定窗口（since=now-hours，until=None，is_custom=False）
      · range=custom 或缺失 + 显式 start/end → 自定义窗口（is_custom=True）
      · 既无 range 也无 start/end → 回退默认窗口（default_range，向后兼容原默认 24h）
    start/end 格式：'%Y-%m-%d %H:%M:%S' 或 unix 时间戳；均为本地时区（Asia/Shanghai）。
    """
    rng = request.GET.get('range')
    if rng in ('24h', '3d', '7d'):
        hours = {'24h': 24, '3d': 72, '7d': 7 * 24}[rng]
        since = timezone.now() - timedelta(hours=hours)
        return since, None, rng, False
    start = _parse_dt(request.GET.get('start'))
    end = _parse_dt(request.GET.get('end'))
    if start or end:
        since = start or (timezone.now() - timedelta(hours=default_hours))
        return since, end, 'custom', True
    # 既无 range 也无起止 → 回退默认窗口（WafStatsView 默认 24h 保证趋势为小时粒度）
    hours = {'24h': 24, '3d': 72, '7d': 7 * 24}.get(default_range, 24)
    since = timezone.now() - timedelta(hours=hours)
    return since, None, default_range, False


# 攻击等级映射（中英文归一）：high→高/严重/high/...；用于 WafLogsView / WafExportView 过滤
_SEV_MAP = {
    'high': ['高', '严重', 'high', 'High', 'HIGH', 'Critical', 'crit'],
    'medium': ['中', 'medium', 'Medium'],
    'low': ['低', 'low', 'Low'],
}


def _build_waf_qs(request, default_hours=24):
    """构造 WAF/FW 攻击日志的过滤 QuerySet（列表与导出共用，保证导出即所见）。
    过滤项：时间窗（_resolve_window：range>start/end>默认24h）+ src_ip/dst_ip/event_type/dev_ip
            + severity（中英文归一）+ device_type（WAF/Firewall）。"""
    qs = WafAttackLog.objects.all()
    start, end, rng, is_custom = _resolve_window(request, default_hours=default_hours)
    qs = qs.filter(log_time__gte=start)
    if end:
        qs = qs.filter(log_time__lte=end)
    for f in ('src_ip', 'dst_ip', 'event_type', 'dev_ip'):
        v = request.GET.get(f)
        if v:
            qs = qs.filter(**{f + '__icontains': v})
    sev = request.GET.get('severity')
    if sev:
        targets = _SEV_MAP.get(sev.lower(), [sev])
        qs = qs.filter(severity__in=targets)
    dt = request.GET.get('device_type')
    if dt:
        qs = qs.filter(device_type=dt)
    return qs


class WafLogsView(APIView):
    """WAF 攻击日志列表（分页 + 过滤）"""
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        # 2026-08-27：统一时间窗 + 过滤（与导出共用 _build_waf_qs，所见即所导）
        qs = _build_waf_qs(request)
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
        # 2026-08-27：统一时间窗解析（支持 24h/3d/7d/custom）
        since, until, rng, is_custom = _resolve_window(request, default_hours=24)
        qs = WafAttackLog.objects.filter(log_time__gte=since)
        if until:
            qs = qs.filter(log_time__lte=until)
        dt = request.GET.get('device_type')
        if dt:
            qs = qs.filter(device_type=dt)
        # 趋势桶跨度（小时）：预设固定值；自定义按实际 span 计算（含两端）
        if is_custom:
            span_seconds = (until - since).total_seconds() if until else 24 * 3600
            hours = int(span_seconds / 3600) + 1
        else:
            hours = {'24h': 24, '3d': 72, '7d': 7 * 24}[rng]

        total = qs.count()
        high_cnt = qs.filter(severity__in=['高', 'high', '严重', 'HIGH', 'Critical', 'crit']).count()

        # 2026-08-25：src/dst 分组聚合优化 —— 单次 annotate 同时拿 count/high/last，消除 N+1 查询
        def _enrich_ip(ip_key):
            rows = qs.values(ip_key).exclude(**{ip_key: ''}).annotate(
                c=Count('id'),
                high=Count('id', filter=Q(severity__in=['高', 'high', '严重', 'HIGH', 'Critical', 'crit'])),
                last=Max('log_time'),
            ).order_by('-c')[:500]
            out = []
            for r in rows:
                out.append({
                    ip_key: r[ip_key], 'c': r['c'], 'high': r['high'],
                    'last': timezone.localtime(r['last']).strftime('%Y-%m-%d %H:%M') if r['last'] else '',
                })
            return out

        src_list = _enrich_ip('src_ip')
        dst_list = _enrich_ip('dst_ip')
        # 攻击类型分布
        types = qs.values('event_type').exclude(event_type='').annotate(c=Count('id')).order_by('-c')[:15]
        # 2026-08-26：趋势时间轴修复 —— 桶 key 必须带日期，否则跨天钟点碰撞：
        #   · 24h 按小时，key='MM-DD HH:00'（跨 0 点不再撞 key，最新一小时不再错位到轴左）
        #   · 7d  按天，  key='MM-DD'（覆盖 since→today 连续自然日，不再塌成 24 点小时环）
        # 做法：直接在 Python 端按「本地时区」分桶（Django 读出的 log_time 已是本地 aware）。
        #   不用 DB 端 TruncHour/TruncDay：实测 SQLite 上其按 UTC 截断且 tzinfo 被忽略，
        #   导致聚合 key 比初始化 key 整晚 8 小时、凌晨日志还被错算到前一天。
        # 性能：仅取已过滤后的 log_time 单列（7d 数千条），纯计数循环，开销可忽略。
        # 桶粒度：预设 24h/3d 按小时；7d 按天；自定义按跨度（<=2天小时，否则天）
        if is_custom and until:
            hourly = (until - since).total_seconds() <= 48 * 3600
        else:
            hourly = rng in ('24h', '3d')
        buckets = {}
        for lt in qs.values_list('log_time', flat=True):
            lt = timezone.localtime(lt)
            key = lt.strftime('%m-%d %H:00') if hourly else lt.strftime('%m-%d')
            buckets[key] = buckets.get(key, 0) + 1
        trend = {}
        if hourly:
            for i in range(hours, -1, -1):
                t = timezone.localtime(since + timedelta(hours=hours - i))
                key = t.strftime('%m-%d %H:00')
                trend[key] = buckets.get(key, 0)
        else:  # 按自然日（since 当日 → until 当日 或 今日，连续无缺口）
            day_start = timezone.localtime(since).replace(hour=0, minute=0, second=0, microsecond=0)
            end_day = timezone.localtime(until).replace(hour=0, minute=0, second=0, microsecond=0) if until else timezone.localtime(timezone.now()).replace(hour=0, minute=0, second=0, microsecond=0)
            cur = day_start
            while cur <= end_day:
                key = cur.strftime('%m-%d')
                trend[key] = buckets.get(key, 0)
                cur = cur + timedelta(days=1)
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


class WafExportView(APIView):
    """WAF/FW 攻击日志 CSV 导出（与列表共用 _build_waf_qs，所见即所导）
    复用时间窗(range/start/end) + 过滤(src_ip/dst_ip/event_type/dev_ip/severity/device_type)。
    返回 text/csv（utf-8-sig BOM，Excel 直接打开中文不乱码）。"""
    authentication_classes = [CSRFExemptSessionAuthentication]

    # 导出列（与 WafAttackLog 模型字段 + 抽屉详情一致）
    COLUMNS = [
        ('log_time', '日志时间'), ('device_type', '设备类型'), ('dev_ip', '设备IP'),
        ('src_ip', '源IP'), ('src_port', '源端口'), ('dst_ip', '目的IP'), ('dst_port', '目的端口'),
        ('event_type', '攻击类型'), ('severity', '危险等级'), ('action', '处置动作'),
        ('rule_id', '规则ID'), ('proto', '协议'), ('protocol_type', '协议类型'),
        ('method', 'HTTP方法'), ('domain', '域名'), ('uri', 'URL'),
        ('site_name', '站点名称'), ('src_country', '源国家'), ('alert_info', '告警信息'),
        ('policy_name', '策略名称'), ('msg', '事件描述'),
    ]

    def get(self, request):
        import csv
        from django.http import HttpResponse
        qs = _build_waf_qs(request).order_by('id')
        resp = HttpResponse(content_type='text/csv')
        resp['Content-Type'] = 'text/csv; charset=utf-8-sig'
        dt = request.GET.get('device_type') or 'all'
        resp['Content-Disposition'] = 'attachment; filename="security_logs_%s.csv"' % dt
        resp.write('\ufeff')  # BOM，保证 Excel 中文不乱码
        writer = csv.writer(resp)
        writer.writerow([c[1] for c in self.COLUMNS])
        fields = [c[0] for c in self.COLUMNS]
        for row in qs.values_list(*fields).iterator(chunk_size=2000):
            writer.writerow(['' if v is None else str(v) for v in row])
        return resp
