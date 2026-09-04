# -*- coding: utf-8 -*-
"""
eSight 概览页聚合 view（5 大安全模块 — 2026-09-01 新增）
- 不再代理平台，5 类数据全在 eSight 本地模型：
  * WAF/FW:     WafAttackLog（device_type 区分）
  * Vuln:       VscanVuln（系统漏洞）+ VscanWebVuln（WEB 漏洞）合并
  * Alert:      AlertRecord（每次扫描的结果快照）
  * Host:       NetworkEquipmentModel（按 ssh_state/snmp_state 统计）
- 前端 dist 通过 /api/control/v0_1/security-overview-{waf,fw,vuln,alert,host}/ 调用
- 输出统一契约（前端 5 张卡片按相同 schema 渲染，含 echarts pie + bar + TOP 列表）
"""
import json
import logging
from datetime import timedelta
from django.db.models import Count, Q
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


# ─────────────── 工具：风险等级标准化（5 类模块统一语义）────────────────
# 中文语义 vs 系统漏洞 severity 0/1/2/3/4
_SYS_SEVERITY_TEXT = {0: '信息', 1: '低', 2: '中', 3: '高', 4: '严重'}
# WEB 漏洞 severity 0/1/2/3（方向反：0=高、1=中、2=低、3=信息）
_WEB_SEVERITY_TEXT = {0: '高', 1: '中', 2: '低', 3: '信息'}


def _severity_buckets():
    """统一返回 5 个等级桶（echarts pie 配色按这个顺序：信息/低/中/高/严重）"""
    return [
        ('信息', 0), ('低', 0), ('中', 0), ('高', 0), ('严重', 0),
    ]


def _bucket_fill(buckets, name, value):
    for i, (n, _) in enumerate(buckets):
        if n == name:
            buckets[i] = (n, value)
            return
    # 兜底追加
    buckets.append((name, value))


def _today_range():
    now = timezone.now()
    return now.replace(hour=0, minute=0, second=0, microsecond=0), now


def _trend_7d_series(today_zero, count_per_day_fn):
    """返回近 7 天 [08-25, ..., 08-31] 计数序列。count_per_day(date) -> int"""
    out = []
    for i in range(6, -1, -1):
        day = today_zero - timedelta(days=i)
        next_day = day + timedelta(days=1)
        try:
            cnt = count_per_day_fn(day, next_day)
        except Exception:
            cnt = 0
        out.append({'date': day.strftime('%m-%d'), 'count': cnt})
    return out


# ════════════════ 1. WAF 攻击日志分析 ════════════════
class SecurityOverviewWafView(APIView):
    """GET /api/control/v0_1/security-overview-waf/ — WAF 攻击日志聚合
    数据源：WafAttackLog（device_type='WAF'）
    输出：totals / severity_dist / trend_7d / top_src_ip
    """
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        try:
            from apps.cmdb.models.waf_security import WafAttackLog
        except Exception as e:
            return ok({'error': 'WafAttackLog 模型加载失败: {}'.format(e)})

        qs = WafAttackLog.objects.filter(device_type='WAF')
        today_zero, now = _today_range()
        sev_total = qs.count()
        sev_today = qs.filter(log_time__gte=today_zero).count()
        # 高危/严重（WAF severity 也是中文字符串，但安全起见按 severity_id 兜底）
        sev_high = qs.filter(Q(severity__in=['高', '严重', '高危']) | Q(severity_id__gte=3)).count()

        # 风险分布
        buckets = _severity_buckets()
        # 先按文本聚合（绿盟 syslog severity 是中文字符串）
        text_rows = qs.values('severity').annotate(c=Count('id'))
        text_map = {'信息': 0, '低': 0, '中': 0, '高': 0, '严重': 0}
        for r in text_rows:
            n = (r.get('severity') or '').strip()
            if n in text_map:
                text_map[n] += r['c']
        # 兜底按数值聚合（severity_id）
        id_rows = qs.values('severity_id').annotate(c=Count('id'))
        for r in id_rows:
            sid = r['severity_id']
            txt = _SYS_SEVERITY_TEXT.get(sid)
            if txt and not text_map.get(txt):  # 仅在文本未覆盖时用数值
                text_map[txt] += r['c']
        sev_dist = [{'name': n, 'value': v} for n, v in text_map.items() if v > 0]

        # 7 日趋势
        trend = _trend_7d_series(
            today_zero,
            lambda d, nd: qs.filter(log_time__gte=d, log_time__lt=nd).count(),
        )

        # TOP 来源 IP：与 WAF 日志详情页 src_top 口径一致（裸 TOP），窗口取“当天”以对齐详情页默认视图。
        top_qs = qs.filter(log_time__gte=today_zero)
        top_rows = top_qs.values('src_ip').exclude(src_ip='').annotate(c=Count('id')).order_by("-c")[:10]
        top_src_ip = [{'label': r['src_ip'] or '未知', 'count': r['c']} for r in top_rows]

        return ok({
            'module': 'waf',
            'title': 'WAF 攻击日志',
            'router': '/security/wafMonitor',
            'totals': {'total': sev_total, 'today': sev_today, 'high': sev_high},
            'severity_dist': sev_dist,
            'trend_7d': trend,
            'top_src_ip': top_src_ip,
        })


# ════════════════ 2. 防火墙日志分析 ════════════════
class SecurityOverviewFwView(APIView):
    """GET /api/control/v0_1/security-overview-fw/ — 防火墙日志聚合（device_type='Firewall'）"""
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        try:
            from apps.cmdb.models.waf_security import WafAttackLog
        except Exception as e:
            return ok({'error': 'WafAttackLog 模型加载失败: {}'.format(e)})

        qs = WafAttackLog.objects.filter(device_type='Firewall')
        today_zero, now = _today_range()
        total = qs.count()
        today = qs.filter(log_time__gte=today_zero).count()
        # 高危/严重：兼容中文+英文 severity（华为 USG 防火墙 syslog 输出 high/medium/low）
        high = qs.filter(
            Q(severity__in=['高', '严重', '高危', 'high']) | Q(severity_id__gte=3)
        ).count()

        # 风险分布 — 防火墙 severity 文本是英文（USG 防火墙 syslog），需英文→中文映射
        # 已知数据（容器内 sqlite 验证）：medium=4210 / high=2339 / low=530 / 空=779
        _FW_SEV_EN2CN = {'high': '高', 'medium': '中', 'low': '低', 'critical': '严重'}
        text_map = {'信息': 0, '低': 0, '中': 0, '高': 0, '严重': 0}
        text_rows = qs.values('severity').annotate(c=Count('id'))
        for r in text_rows:
            raw = (r.get('severity') or '').strip()
            if not raw:
                # 空 severity 归"信息"（兜底）
                text_map['信息'] += r['c']
                continue
            if raw in text_map:
                text_map[raw] += r['c']
            elif raw in _FW_SEV_EN2CN:
                text_map[_FW_SEV_EN2CN[raw]] += r['c']
            # 其他无法识别的 severity 不归任何桶（避免污染）
        # severity_id 兜底（仅在文本未填且 sid>=1 时启用；USG syslog 解析时 sid 全为 0 不可信）
        id_rows = qs.values('severity_id').annotate(c=Count('id'))
        for r in id_rows:
            sid = r['severity_id']
            if sid is None or sid <= 0:
                continue
            txt = _SYS_SEVERITY_TEXT.get(sid)
            if txt and text_map.get(txt, 0) == 0:
                text_map[txt] += r['c']
        sev_dist = [{'name': n, 'value': v} for n, v in text_map.items() if v > 0]

        trend = _trend_7d_series(
            today_zero,
            lambda d, nd: qs.filter(log_time__gte=d, log_time__lt=nd).count(),
        )

        # TOP 来源 IP：与防火墙日志详情页 src_top 口径一致（裸 TOP），窗口取“当天”以对齐详情页默认视图。
        top_qs = qs.filter(log_time__gte=today_zero)
        top_rows = top_qs.values('src_ip').exclude(src_ip='').annotate(c=Count('id')).order_by("-c")[:10]
        top_src_ip = [{'label': r['src_ip'] or '未知', 'count': r['c']} for r in top_rows]

        return ok({
            'module': 'fw',
            'title': '防火墙日志',
            'router': '/security/fwMonitor',
            'totals': {'total': total, 'today': today, 'high': high},
            'severity_dist': sev_dist,
            'trend_7d': trend,
            'top_src_ip': top_src_ip,
        })


# ════════════════ 3. 漏洞扫描分析（系统+WEB 合并） ════════════════
class SecurityOverviewVulnView(APIView):
    """GET /api/control/v0_1/security-overview-vuln/ — 漏洞扫描聚合
    数据源：VscanVuln（系统漏洞，severity 0信息/1低/2中/3高/4严重）
            VscanWebVuln（WEB 漏洞，severity 0高/1中/2低/3信息，方向反！）
    合并语义：
      total = 系统 + WEB
      high  = 系统 severity>=3 + WEB severity==0
    """
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        try:
            from apps.cmdb.models.vscan_sys import VscanVuln
            from apps.cmdb.models.vscan_web import VscanWebVuln
        except Exception as e:
            return ok({'error': '漏洞模型加载失败: {}'.format(e)})

        sys_qs = VscanVuln.objects.all()
        web_qs = VscanWebVuln.objects.all()

        sys_total = sys_qs.count()
        web_total = web_qs.count()
        sys_high = sys_qs.filter(severity__gte=3).count()  # 严重/高
        web_high = web_qs.filter(severity=0).count()       # WEB 0=高（方向反，铁律！）

        # 系统漏洞分布（按文本）
        sys_text = {'信息': 0, '低': 0, '中': 0, '高': 0, '严重': 0}
        for r in sys_qs.values('severity').annotate(c=Count('id')):
            sid = r['severity']
            txt = _SYS_SEVERITY_TEXT.get(sid)
            if txt:
                sys_text[txt] += r['c']

        # WEB 漏洞分布（方向反）
        web_text = {'信息': 0, '低': 0, '中': 0, '高': 0, '严重': 0}
        for r in web_qs.values('severity').annotate(c=Count('id')):
            sid = r['severity']
            txt = _WEB_SEVERITY_TEXT.get(sid)
            if txt:
                web_text[txt] += r['c']

        # 合并（5 桶）
        merged = {k: sys_text[k] + web_text[k] for k in sys_text}
        sev_dist = [{'name': n, 'value': v} for n, v in merged.items() if v > 0]

        # 7 日趋势：系统 sync_time + WEB scan_time（按"日"聚合）
        today_zero, _ = _today_range()

        def _count_vuln(day, next_day):
            a = sys_qs.filter(sync_time__gte=day, sync_time__lt=next_day).count()
            b = web_qs.filter(scan_time__gte=day, scan_time__lt=next_day, scan_time__isnull=False).count()
            return a + b

        trend = _trend_7d_series(today_zero, _count_vuln)

        # TOP 5 高漏洞名（系统 + WEB 合并）
        sys_top = list(sys_qs.filter(severity__gte=3).values('name').annotate(c=Count('id')).order_by("-c")[:5])
        web_top = list(web_qs.filter(severity=0).values('name').annotate(c=Count('id')).order_by("-c")[:5])
        seen = set()
        top_vulns = []
        for r in sys_top + web_top:
            n = (r['name'] or '').strip()
            if n and n not in seen:
                seen.add(n)
                top_vulns.append({'label': n[:60], 'count': r['c']})
                if len(top_vulns) >= 8:
                    break

        return ok({
            'module': 'vuln',
            'title': '漏洞扫描',
            'router': '/security/vscanMonitor',
            'totals': {
                'sys_total': sys_total,
                'web_total': web_total,
                'total': sys_total + web_total,
                'sys_high': sys_high,
                'web_high': web_high,
                'high': sys_high + web_high,
            },
            'severity_dist': sev_dist,
            'trend_7d': trend,
            'top_vulns': top_vulns,
        })


# ════════════════ 4. 安全告警分析 ════════════════
class SecurityOverviewAlertView(APIView):
    """GET /api/control/v0_1/security-overview-alert/ — 安全告警聚合
    数据源：AlertRecord（每次扫描的快照）
    关键字段：events_new / events_resolved / waf_new / fw_new / vuln_high / web_high
    """
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        try:
            from apps.cmdb.models.security_alert import AlertRecord
        except Exception as e:
            return ok({'error': 'AlertRecord 模型加载失败: {}'.format(e)})

        qs = AlertRecord.objects.all()
        today_zero, _ = _today_range()
        total = qs.count()
        today = qs.filter(scan_time__gte=today_zero).count()

        # 累计告警事件
        agg = qs.aggregate(
            events_new_sum=Count('id', filter=Q(events_new__gt=0)),
            events_resolved_sum=Count('id', filter=Q(events_resolved__gt=0)),
        )

        # 最近一次告警的核心数据
        last = qs.first()  # ordering = ['-scan_time']
        latest = None
        if last:
            latest = {
                'scan_time': last.scan_time.strftime('%Y-%m-%d %H:%M:%S') if last.scan_time else None,
                'trigger': last.trigger,
                'events_new': last.events_new,
                'events_resolved': last.events_resolved,
                'events_recurred': last.events_recurred,
                'events_suppressed': last.events_suppressed,
                'waf_new': last.waf_new,
                'fw_new': last.fw_new,
                'vuln_high': last.vuln_high,
                'web_high': last.web_high,
                'notified': last.notified,
                'channels': last.channels,
            }

        # 7 日触发趋势（按日统计 AlertRecord 数）
        trend = _trend_7d_series(
            today_zero,
            lambda d, nd: qs.filter(scan_time__gte=d, scan_time__lt=nd).count(),
        )

        return ok({
            'module': 'alert',
            'title': '安全告警',
            'router': '/security/securityAlert',
            'totals': {
                'total': total,
                'today': today,
                'scans_with_event': agg.get('events_new_sum', 0) or 0,
                'scans_with_resolved': agg.get('events_resolved_sum', 0) or 0,
            },
            'latest': latest,
            'trend_7d': trend,
        })


# ════════════════ 5. 主机监控分析 ════════════════
class SecurityOverviewHostView(APIView):
    """GET /api/control/v0_1/security-overview-host/ — 主机监控聚合
    数据源：NetworkEquipmentModel
    状态字段：ssh_state / snmp_state / telnet_state（'0'未纳管 / '1'正常 / '2'异常）
    监控方式：monitor_type（ssh/snmp/zabbix 等）
    """
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        try:
            from apps.cmdb.models.control_models import NetworkEquipmentModel
        except Exception as e:
            return ok({'error': 'NetworkEquipmentModel 模型加载失败: {}'.format(e)})

        qs = NetworkEquipmentModel.objects.all()
        total = qs.count()

        # SSH 状态
        ssh_normal = qs.filter(ssh_state='1').count()
        ssh_error = qs.filter(ssh_state='2').count()
        ssh_never = qs.filter(ssh_state='0').count()
        # SNMP 状态
        snmp_normal = qs.filter(snmp_state='1').count()
        snmp_error = qs.filter(snmp_state='2').count()
        snmp_never = qs.filter(snmp_state='0').count()
        # 监控方式分布
        mt_rows = qs.values('monitor_type').annotate(c=Count('id'))
        monitor_dist = [
            {'name': (r['monitor_type'] or '未配置') if r['monitor_type'] else '未配置', 'value': r['c']}
            for r in mt_rows if r['c'] > 0
        ]

        # 7 日趋势：按 created_at（BaseModel 自带）统计新增设备数
        today_zero, _ = _today_range()
        trend = _trend_7d_series(
            today_zero,
            lambda d, nd: qs.filter(created_at__gte=d, created_at__lt=nd).count(),
        )

        # 异常主机 TOP 5（ssh_state=2 优先，按 ip 排序）
        err_rows = qs.filter(ssh_state='2').values('id', 'name', 'ip', 'ssh_state_message')[:5]
        err_hosts = [
            {'label': '{} {}'.format(r['name'] or '?',r['ip'] or '').strip(), 'count': 1, 'msg': r['ssh_state_message'] or ''}
            for r in err_rows
        ]

        return ok({
            'module': 'host',
            'title': '主机监控',
            'router': '/network/hostMonitor',
            'totals': {
                'total': total,
                'ssh_normal': ssh_normal,
                'ssh_error': ssh_error,
                'ssh_never': ssh_never,
                'snmp_normal': snmp_normal,
                'snmp_error': snmp_error,
                'snmp_never': snmp_never,
            },
            'monitor_dist': monitor_dist,
            'trend_7d': trend,
            'err_hosts': err_hosts,
        })