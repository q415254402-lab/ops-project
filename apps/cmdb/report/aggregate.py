# -*- coding: utf-8 -*-
"""安全报表聚合引擎（日/周/月通用）

复用 overview_views 的 5 模块聚合逻辑，但窗口参数化（start, end），
供 Celery 定时任务落库，以及 API 实时计算共用。

独立实现（不直接 import overview_views 的 APIView），避免对已上线概览造成回归风险；
小工具函数（_SYS_SEVERITY_TEXT / _WEB_SEVERITY_TEXT 等）保持与 overview 一致语义。
"""
from datetime import timedelta
from django.db.models import Count, Q

# ── 风险等级标准化（与 overview_views 保持一致）──
_SYS_SEVERITY_TEXT = {0: '信息', 1: '低', 2: '中', 3: '高', 4: '严重'}
_WEB_SEVERITY_TEXT = {0: '高', 1: '中', 2: '低', 3: '信息'}


def _trend_in_period(start, end, count_per_day_fn):
    """按 start~end 的自然日逐日计数（闭开区间 [start, end)）"""
    out = []
    day = start.replace(hour=0, minute=0, second=0, microsecond=0)
    while day < end:
        next_day = day + timedelta(days=1)
        if next_day > end:
            next_day = end
        try:
            cnt = count_per_day_fn(day, next_day)
        except Exception:
            cnt = 0
        out.append({'date': day.strftime('%Y-%m-%d'), 'count': cnt})
        day = next_day
    return out


def aggregate_waf(start, end):
    from apps.cmdb.models import WafAttackLog
    qs = WafAttackLog.objects.filter(device_type='WAF')
    window_qs = qs.filter(log_time__gte=start, log_time__lt=end)
    total = window_qs.count()
    high = window_qs.filter(Q(severity__in=['高', '严重', '高危']) | Q(severity_id__gte=3)).count()
    text_map = {'信息': 0, '低': 0, '中': 0, '高': 0, '严重': 0}
    for r in window_qs.values('severity').annotate(c=Count('id')):
        n = (r.get('severity') or '').strip()
        if n in text_map:
            text_map[n] += r['c']
    id_rows = window_qs.values('severity_id').annotate(c=Count('id'))
    for r in id_rows:
        sid = r['severity_id']
        txt = _SYS_SEVERITY_TEXT.get(sid)
        if txt and not text_map.get(txt):
            text_map[txt] += r['c']
    sev_dist = [{'name': n, 'value': v} for n, v in text_map.items() if v > 0]
    trend = _trend_in_period(start, end,
                             lambda d, nd: window_qs.filter(log_time__gte=d, log_time__lt=nd).count())
    top_rows = window_qs.values('src_ip').exclude(src_ip='').annotate(c=Count('id')).order_by('-c')[:10]
    top_src_ip = [{'label': r['src_ip'] or '未知', 'count': r['c']} for r in top_rows]
    return {'totals': {'total': total, 'high': high}, 'severity_dist': sev_dist,
            'trend': trend, 'top_src_ip': top_src_ip}


def aggregate_fw(start, end):
    from apps.cmdb.models import WafAttackLog
    qs = WafAttackLog.objects.filter(device_type='Firewall')
    window_qs = qs.filter(log_time__gte=start, log_time__lt=end)
    total = window_qs.count()
    high = window_qs.filter(
        Q(severity__in=['高', '严重', '高危', 'high']) | Q(severity_id__gte=3)
    ).count()
    _FW_SEV_EN2CN = {'high': '高', 'medium': '中', 'low': '低', 'critical': '严重'}
    text_map = {'信息': 0, '低': 0, '中': 0, '高': 0, '严重': 0}
    for r in window_qs.values('severity').annotate(c=Count('id')):
        raw = (r.get('severity') or '').strip()
        if not raw:
            text_map['信息'] += r['c']
            continue
        if raw in text_map:
            text_map[raw] += r['c']
        elif raw in _FW_SEV_EN2CN:
            text_map[_FW_SEV_EN2CN[raw]] += r['c']
    id_rows = window_qs.values('severity_id').annotate(c=Count('id'))
    for r in id_rows:
        sid = r['severity_id']
        if sid is None or sid <= 0:
            continue
        txt = _SYS_SEVERITY_TEXT.get(sid)
        if txt and text_map.get(txt, 0) == 0:
            text_map[txt] += r['c']
    sev_dist = [{'name': n, 'value': v} for n, v in text_map.items() if v > 0]
    trend = _trend_in_period(start, end,
                             lambda d, nd: window_qs.filter(log_time__gte=d, log_time__lt=nd).count())
    top_rows = window_qs.values('src_ip').exclude(src_ip='').annotate(c=Count('id')).order_by('-c')[:10]
    top_src_ip = [{'label': r['src_ip'] or '未知', 'count': r['c']} for r in top_rows]
    return {'totals': {'total': total, 'high': high}, 'severity_dist': sev_dist,
            'trend': trend, 'top_src_ip': top_src_ip}


def aggregate_vuln(start, end):
    from apps.cmdb.models import VscanVuln, VscanWebVuln
    sys_qs = VscanVuln.objects.filter(sync_time__gte=start, sync_time__lt=end)
    web_qs = VscanWebVuln.objects.filter(scan_time__gte=start, scan_time__lt=end, scan_time__isnull=False)
    sys_total = sys_qs.count()
    web_total = web_qs.count()
    sys_high = sys_qs.filter(severity__gte=3).count()
    web_high = web_qs.filter(severity=0).count()
    sys_text = {'信息': 0, '低': 0, '中': 0, '高': 0, '严重': 0}
    for r in sys_qs.values('severity').annotate(c=Count('id')):
        txt = _SYS_SEVERITY_TEXT.get(r['severity'])
        if txt:
            sys_text[txt] += r['c']
    web_text = {'信息': 0, '低': 0, '中': 0, '高': 0, '严重': 0}
    for r in web_qs.values('severity').annotate(c=Count('id')):
        txt = _WEB_SEVERITY_TEXT.get(r['severity'])
        if txt:
            web_text[txt] += r['c']
    merged = {k: sys_text[k] + web_text[k] for k in sys_text}
    sev_dist = [{'name': n, 'value': v} for n, v in merged.items() if v > 0]
    trend = _trend_in_period(
        start, end,
        lambda d, nd: sys_qs.filter(sync_time__gte=d, sync_time__lt=nd).count()
        + web_qs.filter(scan_time__gte=d, scan_time__lt=nd, scan_time__isnull=False).count()
    )
    sys_top = list(sys_qs.filter(severity__gte=3).values('name').annotate(c=Count('id')).order_by('-c')[:5])
    web_top = list(web_qs.filter(severity=0).values('name').annotate(c=Count('id')).order_by('-c')[:5])
    seen = set()
    top_vulns = []
    for r in sys_top + web_top:
        n = (r['name'] or '').strip()
        if n and n not in seen:
            seen.add(n)
            top_vulns.append({'label': n[:60], 'count': r['c']})
            if len(top_vulns) >= 8:
                break
    return {
        'totals': {
            'sys_total': sys_total, 'web_total': web_total,
            'total': sys_total + web_total,
            'sys_high': sys_high, 'web_high': web_high, 'high': sys_high + web_high,
        },
        'severity_dist': sev_dist, 'trend': trend, 'top_vulns': top_vulns,
    }


def aggregate_alert(start, end):
    from apps.cmdb.models import AlertRecord
    qs = AlertRecord.objects.filter(scan_time__gte=start, scan_time__lt=end)
    total = qs.count()
    agg = qs.aggregate(
        events_new=Count('id', filter=Q(events_new__gt=0)),
        events_resolved=Count('id', filter=Q(events_resolved__gt=0)),
    )
    last = qs.order_by('-scan_time').first()
    latest = None
    if last:
        latest = {
            'scan_time': last.scan_time.strftime('%Y-%m-%d %H:%M:%S') if last.scan_time else None,
            'trigger': last.trigger,
            'events_new': last.events_new,
            'events_resolved': last.events_resolved,
            'waf_new': last.waf_new,
            'fw_new': last.fw_new,
            'vuln_high': last.vuln_high,
            'web_high': last.web_high,
            'notified': last.notified,
            'channels': last.channels,
        }
    trend = _trend_in_period(start, end,
                             lambda d, nd: qs.filter(scan_time__gte=d, scan_time__lt=nd).count())
    return {
        'totals': {
            'total': total,
            'scans_with_event': agg.get('events_new', 0) or 0,
            'scans_with_resolved': agg.get('events_resolved', 0) or 0,
        },
        'latest': latest, 'trend': trend,
    }


def aggregate_host(start, end):
    """主机监控聚合

    ⚠️ 2026-09-04 修正两处缺陷：
      1. trend 过滤字段原为 created_at，但 NetworkEquipmentModel 只有 create_time，
         FieldError 被 _trend_in_period 的 except 吞成 0 → 主机 trend 恒为 0。
      2. NetworkEquipmentModel 无状态历史表，totals 是"当前快照"而非"当时状态"，
         任何周期窗口查出来都一样。返回 meta.snapshot=True 供前端标注，避免误导。
    """
    from apps.cmdb.models import NetworkEquipmentModel
    qs = NetworkEquipmentModel.objects.all()
    total = qs.count()
    ssh_normal = qs.filter(ssh_state='1').count()
    ssh_error = qs.filter(ssh_state='2').count()
    ssh_never = qs.filter(ssh_state='0').count()
    snmp_normal = qs.filter(snmp_state='1').count()
    snmp_error = qs.filter(snmp_state='2').count()
    snmp_never = qs.filter(snmp_state='0').count()
    mt_rows = qs.values('monitor_type').annotate(c=Count('id'))
    monitor_dist = [
        {'name': (r['monitor_type'] or '未配置') if r['monitor_type'] else '未配置', 'value': r['c']}
        for r in mt_rows if r['c'] > 0
    ]
    # 字段是 create_time 不是 created_at（原写法每天抛 FieldError 被静默吞成 0）
    trend = _trend_in_period(start, end,
                             lambda d, nd: qs.filter(create_time__gte=d, create_time__lt=nd).count())
    err_rows = qs.filter(ssh_state='2').values('name', 'ip', 'ssh_state_message')[:5]
    err_hosts = [
        {'label': '%s %s' % ((r['name'] or '?'), r['ip'] or '').strip(), 'count': 1,
         'msg': r['ssh_state_message'] or ''}
        for r in err_rows
    ]
    return {
        'totals': {
            'total': total, 'ssh_normal': ssh_normal, 'ssh_error': ssh_error, 'ssh_never': ssh_never,
            'snmp_normal': snmp_normal, 'snmp_error': snmp_error, 'snmp_never': snmp_never,
        },
        'monitor_dist': monitor_dist, 'trend': trend, 'err_hosts': err_hosts,
        'meta': {'snapshot': True, 'note': '主机为当前快照，不随所选周期变化'},
    }


def aggregate_security(start, end):
    return {
        'waf': aggregate_waf(start, end),
        'fw': aggregate_fw(start, end),
        'vuln': aggregate_vuln(start, end),
        'alert': aggregate_alert(start, end),
        'host': aggregate_host(start, end),
    }


# 各模块用于环比的可比指标
_COMPARE_KEYS = {
    'waf': ['total', 'high'],
    'fw': ['total', 'high'],
    'vuln': ['total', 'high'],
    'alert': ['total', 'scans_with_event'],
    'host': ['total', 'ssh_error', 'snmp_error'],
}


def _cmp(cur_module, prev_module, keys):
    out = {}
    for k in keys:
        c = cur_module.get('totals', {}).get(k)
        if c is None:
            continue
        p = prev_module.get('totals', {}).get(k) or 0
        item = {'cur': c, 'prev': p, 'delta': c - p}
        item['pct'] = round((c - p) * 100.0 / p, 1) if p else None
        out[k] = item
    return out


def build_report(period_type, start, end, prev_start, prev_end):
    cur = aggregate_security(start, end)
    prev = aggregate_security(prev_start, prev_end)
    compare = {}
    for mod in ('waf', 'fw', 'vuln', 'alert', 'host'):
        compare[mod] = _cmp(cur.get(mod, {}), prev.get(mod, {}), _COMPARE_KEYS.get(mod, []))
    return {
        'period_type': period_type,
        'period_start': start.strftime('%Y-%m-%d %H:%M:%S'),
        'period_end': end.strftime('%Y-%m-%d %H:%M:%S'),
        'modules': cur,
        'compare': compare,
    }
