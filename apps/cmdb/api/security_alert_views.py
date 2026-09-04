# -*- coding: utf-8 -*-
"""安全告警 API（2026-08-28 深化版）

- AlertRuleView        GET/POST  规则（含调度/冷却/恢复/未知级别）
- AlertScanView        POST      立即检测（带收敛）
- AlertRecordListView  GET       扫描记录（审计）
- AlertEventListView   GET       告警事件列表（筛选 + 分页）
- AlertEventActionView POST      事件运营操作（确认 / 取消确认 / 忽略 / 重新打开）
- AlertEventStatsView  GET       事件统计卡
- AlertEventDetailView GET       事件详情钻取（概要 + 原始攻击日志分页 + 跳转链接）

推送通道（钉钉/邮件）可插拔：无凭据时仅落库不发送（测试环境零配置可跑）。
"""
import json
import logging

from django.utils import timezone
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated

from apps.cmdb.models import AlertRule, AlertRecord, AlertEvent, WafAttackLog
from apps.cmdb.api.waf_views import _SEV_MAP
from apps.cmdb.models_alert_engine import run_alert_scan_manual, event_stats

logger = logging.getLogger('app')


class CSRFExemptSessionAuthentication(SessionAuthentication):
    def enforce_csrf(self, request):
        return


# 阈值 -> 包含的 WAF severity 级别（_SEV_MAP 的 key）
_THR_LEVELS = {
    'high': ['high'],
    'medium': ['high', 'medium'],
    'low': ['high', 'medium', 'low'],
}
# 阈值 -> WEB 漏洞 severity 上限（WEB: 0高/1中/2低/3信息，方向反）
_WEB_THR = {'high': 0, 'medium': 1, 'low': 2}


def _sev_strings(thr):
    s = set()
    for lvl in _THR_LEVELS.get(thr, ['high']):
        s.update(_SEV_MAP.get(lvl, []))
    return list(s)


# ---------------------------------------------------------------- 序列化
def _rule_dict(rule):
    return {
        'severity_threshold': rule.severity_threshold,
        'window_minutes': rule.window_minutes,
        'enabled': rule.enabled,
        'scan_interval_minutes': getattr(rule, 'scan_interval_minutes', 60),
        'cooldown_minutes': getattr(rule, 'cooldown_minutes', 60),
        'resolve_after_minutes': getattr(rule, 'resolve_after_minutes', 120),
        'notify_on_resolve': getattr(rule, 'notify_on_resolve', True),
        'include_unknown_severity': getattr(rule, 'include_unknown_severity', False),
        'dingtalk_enabled': rule.dingtalk_enabled,
        'dingtalk_webhook': rule.dingtalk_webhook,
        'email_enabled': rule.email_enabled,
        'email_to': rule.email_to,
        'email_subject_prefix': rule.email_subject_prefix,
        'updated_at': rule.updated_at.strftime('%Y-%m-%d %H:%M:%S') if rule.updated_at else '',
    }


def _rec_dict(rec):
    return {
        'id': rec.id,
        'scan_time': rec.scan_time.strftime('%Y-%m-%d %H:%M:%S'),
        'trigger': getattr(rec, 'trigger', 'manual'),
        'window_minutes': rec.window_minutes,
        'severity_threshold': rec.severity_threshold,
        'waf_new': rec.waf_new,
        'fw_new': rec.fw_new,
        'vuln_high': rec.vuln_high,
        'web_high': rec.web_high,
        'total_new': rec.total_new,
        'events_new': getattr(rec, 'events_new', 0),
        'events_recurred': getattr(rec, 'events_recurred', 0),
        'events_resolved': getattr(rec, 'events_resolved', 0),
        'events_suppressed': getattr(rec, 'events_suppressed', 0),
        'notified': getattr(rec, 'notified', False),
        'channels': rec.channels,
    }


def _event_dict(ev):
    return {
        'id': ev.id,
        'fingerprint': ev.fingerprint,
        'fingerprint_short': ev.fingerprint[:12],
        'source': ev.source,
        'event_type': ev.event_type,
        'src_ip': ev.src_ip,
        'dst_ip': ev.dst_ip,
        'severity': ev.severity,
        'status': ev.status,
        'occurrence': ev.occurrence,
        'notify_count': ev.notify_count,
        'first_seen': ev.first_seen.strftime('%Y-%m-%d %H:%M:%S') if ev.first_seen else '',
        'last_seen': ev.last_seen.strftime('%Y-%m-%d %H:%M:%S') if ev.last_seen else '',
        'last_notified_at': ev.last_notified_at.strftime('%Y-%m-%d %H:%M:%S') if ev.last_notified_at else '',
        'resolved_at': ev.resolved_at.strftime('%Y-%m-%d %H:%M:%S') if ev.resolved_at else '',
        'acked_by': ev.acked_by,
        'ack_note': ev.ack_note,
    }


# ---------------------------------------------------------------- 规则
class AlertRuleView(APIView):
    authentication_classes = [CSRFExemptSessionAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        rule, _ = AlertRule.objects.get_or_create(id=1)
        return Response(_rule_dict(rule))

    def post(self, request):
        rule, _ = AlertRule.objects.get_or_create(id=1)
        d = request.data
        if 'severity_threshold' in d:
            rule.severity_threshold = d['severity_threshold']
        for f in ('window_minutes', 'scan_interval_minutes',
                  'cooldown_minutes', 'resolve_after_minutes'):
            if f in d:
                try:
                    setattr(rule, f, int(d[f]))
                except (ValueError, TypeError):
                    pass
        for f in ('enabled', 'notify_on_resolve', 'include_unknown_severity',
                  'dingtalk_enabled', 'email_enabled'):
            if f in d:
                setattr(rule, f, bool(d[f]))
        for f in ('dingtalk_webhook', 'email_to', 'email_subject_prefix'):
            if f in d:
                setattr(rule, f, d[f])
        rule.save()
        return Response(_rule_dict(rule))


# ---------------------------------------------------------------- 扫描
class AlertScanView(APIView):
    authentication_classes = [CSRFExemptSessionAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        rule, _ = AlertRule.objects.get_or_create(id=1)
        try:
            rec, detail = run_alert_scan_manual(rule)
        except Exception as e:
            logger.error('alert scan failed: %s', e)
            return Response({'ok': False, 'error': str(e)}, status=500)
        return Response({
            'ok': True,
            'record': _rec_dict(rec),
            'detail': detail,
        })


# ---------------------------------------------------------------- 扫描记录
class AlertRecordListView(APIView):
    authentication_classes = [CSRFExemptSessionAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        qs = AlertRecord.objects.all()[:50]
        return Response({'results': [_rec_dict(r) for r in qs]})


# ---------------------------------------------------------------- 事件列表
class AlertEventListView(APIView):
    """告警事件列表：支持 status / source / keyword 筛选 + 分页。"""
    authentication_classes = [CSRFExemptSessionAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        status = request.GET.get('status', '').strip()
        source = request.GET.get('source', '').strip()
        kw = request.GET.get('keyword', '').strip()
        try:
            page = int(request.GET.get('page', '1'))
        except (ValueError, TypeError):
            page = 1
        try:
            page_size = int(request.GET.get('page_size', '20'))
        except (ValueError, TypeError):
            page_size = 20
        page_size = max(1, min(page_size, 100))

        qs = AlertEvent.objects.all()
        if status:
            qs = qs.filter(status=status)
        if source:
            qs = qs.filter(source=source)
        if kw:
            from django.db.models import Q
            qs = qs.filter(
                Q(event_type__icontains=kw) | Q(src_ip__icontains=kw) |
                Q(dst_ip__icontains=kw) | Q(fingerprint__icontains=kw)
            )

        total = qs.count()
        start = (page - 1) * page_size
        rows = qs[start:start + page_size]
        return Response({
            'total': total,
            'page': page,
            'page_size': page_size,
            'results': [_event_dict(r) for r in rows],
            'stats': event_stats(),
        })


# ---------------------------------------------------------------- 事件运营
class AlertEventActionView(APIView):
    """事件运营操作：ack / unack / suppress / reopen。"""
    authentication_classes = [CSRFExemptSessionAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        fp = (request.data.get('fingerprint') or '').strip()
        action = (request.data.get('action') or '').strip()
        operator = (request.data.get('operator') or '').strip()
        note = (request.data.get('note') or '').strip()

        if not fp or action not in ('ack', 'unack', 'suppress', 'reopen'):
            return Response({'ok': False, 'error': 'fingerprint/action 参数无效'}, status=400)

        try:
            ev = AlertEvent.objects.get(fingerprint=fp)
        except AlertEvent.DoesNotExist:
            return Response({'ok': False, 'error': '事件不存在'}, status=404)

        now = timezone.now()
        if action == 'ack':
            ev.status = 'acked'
            ev.acked_by = operator
            ev.ack_note = note
        elif action == 'unack':
            # 取消确认：回到 firing（若已恢复则保持 resolved）
            if ev.status == 'acked':
                ev.status = 'firing'
            ev.acked_by = ''
            ev.ack_note = note
        elif action == 'suppress':
            ev.status = 'suppressed'
            ev.acked_by = operator
            ev.ack_note = note
        elif action == 'reopen':
            ev.status = 'firing'
            ev.resolved_at = None
            ev.acked_by = operator
            ev.ack_note = note
        ev.save()
        return Response({'ok': True, 'event': _event_dict(ev), 'stats': event_stats()})


# ---------------------------------------------------------------- 统计
class AlertEventStatsView(APIView):
    authentication_classes = [CSRFExemptSessionAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(event_stats())


# ---------------------------------------------------------------- 事件详情钻取
def _human_dur(sec):
    sec = int(sec)
    if sec < 60:
        return '%d秒' % sec
    m, sec = divmod(sec, 60)
    if m < 60:
        return '%d分%d秒' % (m, sec)
    h, m = divmod(m, 60)
    if h < 24:
        return '%d时%d分' % (h, m)
    d, h = divmod(h, 24)
    return '%d天%d时' % (d, h)


def _waf_log_dict(r):
    """把 WafAttackLog 行转成可 JSON 序列化的 dict（跳过关联字段）。"""
    d = {}
    for f in r._meta.fields:
        if f.is_relation:
            continue
        v = getattr(r, f.name)
        if hasattr(v, 'isoformat'):
            v = v.isoformat()
        d[f.name] = v
    return d


class AlertEventDetailView(APIView):
    """事件详情钻取：返回事件概要 + 该指纹下原始攻击日志（分页）+ 跳转链接。

    反查逻辑：用事件存储的 source/event_type/src_ip/dst_ip 直接查 WafAttackLog，
    无需改动数据表、无数据迁移；若严格四元组命中为 0，则退化为按 source+双IP 匹配
    （防 event_type 归一化差异导致的漏匹配）。
    """
    authentication_classes = [CSRFExemptSessionAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        fp = (request.GET.get('fingerprint') or '').strip()
        if not fp:
            return Response({'ok': False, 'error': 'fingerprint 必填'}, status=400)
        try:
            ev = AlertEvent.objects.get(fingerprint=fp)
        except AlertEvent.DoesNotExist:
            return Response({'ok': False, 'error': '事件不存在'}, status=404)

        try:
            page = int(request.GET.get('page', '1'))
        except (ValueError, TypeError):
            page = 1
        try:
            page_size = int(request.GET.get('page_size', '20'))
        except (ValueError, TypeError):
            page_size = 20
        page_size = max(1, min(page_size, 200))

        qs = WafAttackLog.objects.filter(
            device_type=ev.source, event_type=ev.event_type,
            src_ip=ev.src_ip, dst_ip=ev.dst_ip).order_by('-log_time')
        if not qs.exists():
            qs = WafAttackLog.objects.filter(
                device_type=ev.source, src_ip=ev.src_ip, dst_ip=ev.dst_ip
            ).order_by('-log_time')

        total = qs.count()
        start = (page - 1) * page_size
        logs = [_waf_log_dict(r) for r in qs[start:start + page_size]]

        event = _event_dict(ev)
        try:
            dur = (ev.last_seen - ev.first_seen).total_seconds()
            event['duration_text'] = _human_dur(dur)
        except Exception:
            event['duration_text'] = '-'

        jump = {
            'waf': '/t/esight/static/waf-monitor/index.html?src_ip=%s' % (ev.src_ip or ''),
            'fw': '/t/esight/static/fw-monitor/index.html?src_ip=%s' % (ev.src_ip or ''),
        }
        return Response({
            'ok': True,
            'event': event,
            'logs': {'total': total, 'page': page, 'page_size': page_size, 'results': logs},
            'jump': jump,
        })
