# -*- coding: utf-8 -*-
"""安全报表 API（日/周/月报）

- GET /api/v1/cmdb/security/report/              → 历史列表（?period_type=day|week|month）
- GET /api/v1/cmdb/security/report/current/      → 实时计算当前周期（?period_type=day|week|month，不落库）
- GET /api/v1/cmdb/security/report/<type>/<key>/ → 详情（返回 data JSON）

2026-09-04：detail / current 均返回 summary 字段（本期总结）
  - detail：从已落库 data['summary'] 取（周/月报由 AI 生成，日报由规则引擎生成）
  - current：实时算，周/月报调 AI 总结（带 120s 超时保护），失败降级规则引擎
"""
import logging
from datetime import timedelta
from django.http import JsonResponse
from django.utils import timezone
from rest_framework.views import APIView
from rest_framework.authentication import SessionAuthentication

logger = logging.getLogger('app')


class CSRFExemptSessionAuthentication(SessionAuthentication):
    def enforce_csrf(self, request):
        return  # 禁用 DRF 强制 CSRF（control dist 默认无 CSRF）


def ok(data=None, msg='信息获取成功'):
    if data is None:
        data = {}
    return JsonResponse({'code': 200, 'successcode': 20005, 'message': msg, 'data': data})


def _period_bounds(period_type, now=None):
    """返回 (start, end) 当前进行中的周期边界（实时卡用）"""
    if now is None:
        now = timezone.localtime(timezone.now())
    if period_type == 'day':
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        return start, now
    if period_type == 'week':
        monday = now - timedelta(days=now.weekday())  # ISO 周一为一周开始
        start = monday.replace(hour=0, minute=0, second=0, microsecond=0)
        return start, now
    if period_type == 'month':
        start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        return start, now
    raise ValueError('unknown period_type: %s' % period_type)


def _summary(r):
    """从已落库的 data JSON 提取摘要指标（供列表页直接画走势图，避免重复聚合）"""
    try:
        mods = (r.get_data() or {}).get('modules') or {}

        def g(m, k):
            return ((mods.get(m) or {}).get('totals') or {}).get(k)

        return {
            'waf': g('waf', 'total'), 'waf_high': g('waf', 'high'),
            'fw': g('fw', 'total'), 'fw_high': g('fw', 'high'),
            'vuln': g('vuln', 'total'), 'vuln_high': g('vuln', 'high'),
            'alert': g('alert', 'total'), 'alert_event': g('alert', 'scans_with_event'),
            'host': g('host', 'total'), 'host_err': g('host', 'snmp_error'),
        }
    except Exception as e:
        logger.warning('report summary extract failed for %s/%s: %s',
                       r.period_type, r.period_key, e)
        return None


class SecurityReportListView(APIView):
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        from apps.cmdb.models import SecurityReport
        period_type = request.GET.get('period_type')
        qs = SecurityReport.objects.all()
        if period_type in ('day', 'week', 'month'):
            qs = qs.filter(period_type=period_type)
        qs = qs.order_by('-period_start')
        # 上限保护：防 DoS（limit=999999 全表扫），int 异常兜底默认值
        try:
            limit = int(request.GET.get('limit', 60))
        except (TypeError, ValueError):
            limit = 60
        limit = max(1, min(limit, 200))
        rows = qs[:limit]
        data = [{
            'period_type': r.period_type,
            'period_key': r.period_key,
            'title': r.title,
            'period_start': r.period_start.strftime('%Y-%m-%d %H:%M:%S'),
            'period_end': r.period_end.strftime('%Y-%m-%d %H:%M:%S'),
            'created_at': r.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'summary': _summary(r),
        } for r in rows]
        return ok({'count': len(data), 'list': data})


class SecurityReportDetailView(APIView):
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request, period_type, period_key):
        from apps.cmdb.models import SecurityReport
        try:
            r = SecurityReport.objects.get(period_type=period_type, period_key=period_key)
        except SecurityReport.DoesNotExist:
            return ok({'error': '报表不存在', 'period_type': period_type, 'period_key': period_key})
        data = r.get_data() or {}
        # 归档详情：summary 已在落库时生成（周/月=AI，日=规则），直接带出
        summary = data.get('summary')
        # 兜底：历史回填前 data['summary'] 可能为空。
        # 铁律：detail 视图只做毫秒级兜底，绝不调 LLM（周/月报归档若空，
        # 调 AI 会阻塞 90s 拖垮用户体验）。只走规则引擎 build_summary。
        # AI 仅用于 /current/ 实时卡（有 120s 超时）和落库时生成（generate_summary_for_report）。
        if not summary or not summary.get('text'):
            try:
                from apps.cmdb.report.summary import build_summary
                rs = build_summary(data)
                parts = ['【概述】风险定级%s：%s' % (rs.get('risk_level', '?'), rs.get('overview', ''))]
                for sec in rs.get('sections') or []:
                    parts.append('【要点】%s：%s' % (sec.get('title', ''), sec.get('text', '')))
                if rs.get('advice'):
                    parts.append('【建议】' + '；'.join(rs['advice']))
                summary = {
                    'text': '\n\n'.join(parts).strip(),
                    'model': 'rule-v1', 'engine': 'rule',
                    'risk_level': rs.get('risk_level'),
                }
            except Exception as e:
                logger.warning('detail view rule summary failed for %s/%s: %s',
                               r.period_type, r.period_key, e)
                summary = None
        return ok({
            'period_type': r.period_type,
            'period_key': r.period_key,
            'title': r.title,
            'period_start': r.period_start.strftime('%Y-%m-%d %H:%M:%S'),
            'period_end': r.period_end.strftime('%Y-%m-%d %H:%M:%S'),
            'data': data,
            'summary': summary,
        })


class SecurityReportCurrentView(APIView):
    """实时计算当前周期（当天/本周/本月至今），不落库

    2026-09-04：周/月报实时卡额外调 AI 总结（带超时保护），失败降级规则引擎。
    日报走规则引擎（毫秒级，不占模型）。
    """
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        from apps.cmdb.report.aggregate import build_report
        period_type = request.GET.get('period_type', 'day')
        if period_type not in ('day', 'week', 'month'):
            return ok({'error': 'period_type 必须是 day/week/month'})
        start, end = _period_bounds(period_type)
        if period_type == 'day':
            prev_end = start
            prev_start = (start - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        elif period_type == 'week':
            prev_end = start
            prev_start = (start - timedelta(days=7)).replace(hour=0, minute=0, second=0, microsecond=0)
        else:  # month
            prev_end = start
            prev_start = (start.replace(day=1) - timedelta(days=1)).replace(day=1,
                                                                            hour=0, minute=0, second=0, microsecond=0)
        report = build_report(period_type, start, end, prev_start, prev_end)
        # 实时总结：周/月报走 AI（带 120s 超时，模型挂时降级规则），日报走规则
        try:
            from apps.cmdb.report.ai_summary import generate_summary
            summary = generate_summary(period_type, report)
            report['summary'] = summary
        except Exception as e:
            logger.warning('current view AI summary failed for %s: %s', period_type, e)
            try:
                from apps.cmdb.report.summary import build_summary
                rs = build_summary(report)
                report['summary'] = {
                    'text': '【概述】%s\n\n【要点】%s' % (
                        rs.get('overview', ''),
                        ' '.join(s.get('text', '') for s in rs.get('sections') or [])),
                    'model': 'rule-v1', 'engine': 'rule', 'risk_level': rs.get('risk_level')}
            except Exception:
                report['summary'] = None
        return ok(report)
