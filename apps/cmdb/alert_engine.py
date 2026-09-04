# -*- coding: utf-8 -*-
"""安全告警收敛引擎（2026-08-28 深化）

对标 Alertmanager 的核心行为：
1. **指纹化（fingerprint）**：按 (source, event_type, src_ip, dst_ip) 归一化生成稳定指纹，
   同一攻击源对同一目标的同类攻击视为**一个事件**，持续复现只累计 occurrence。
2. **冷却抑制（cooldown）**：同一 fingerprint 在冷却期内不重复推送，避免持续扫描型噪声刷屏；
   但 occurrence 持续累加，消息中体现"已持续 N 次 / M 分钟"。
3. **恢复检测（resolve）**：事件超过 resolve_after_minutes 未再出现，自动置为 resolved，
   并（按规则）推送恢复通知 —— 这是告警闭环的关键，避免"只知道出事不知道好了"。
4. **运营状态**：acked（已确认，抑制后续推送）/ suppressed（已忽略，永久不再报）。

推送判定优先级（单事件维度）：
- status in (acked, suppressed) → 不推送
- 新增事件（首次出现）→ 立即推送
- 复现事件但冷却期内 → 抑制（计入 events_suppressed）
- 复现事件且超出冷却期 → 推送（并注明持续时长）
"""
import hashlib
import logging

from django.db.models import Max
from django.utils import timezone
from datetime import timedelta

logger = logging.getLogger('app')

# 空 severity 的归一化取值（仅当规则开启 include_unknown_severity 时纳入）
UNKNOWN_SEVERITY = 'unknown'

# VscanVuln.severity 标度（经容器内实测确认，符合"高危占少数"的现实分布）：
#   1=低危, 2=中危, 3=高危（无 0 值）
# 因此"系统漏洞高危(现状)"定义为 severity >= 该阈值。
# 该标度由 vScan 扫描器决定，非 Django choices 强制；若将来扫描器改标度，
# 下方运行时自检会在高危占比异常（>50%）时打 WARNING，避免静默反向计数。
VULN_HIGH_SEVERITY_MIN = 3


def make_fingerprint(source, event_type, src_ip, dst_ip):
    """生成稳定指纹：归一化后 SHA256 前 32 位（十六进制）。

    归一化规则：统一小写 + 去首尾空格；空值统一为 '-'。
    这样 'Worm Xred' 与 'worm xred' 视为同一事件，避免大小写差异造成指纹分裂。
    """
    def norm(v):
        return (str(v or '').strip().lower()) or '-'
    raw = u'|'.join([norm(source), norm(event_type), norm(src_ip), norm(dst_ip)])
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()[:32]


def severity_queryset_values(rule, base_qs, sev_values):
    """按规则决定是否把空 severity 纳入统计。

    sev_values: 由 _sev_strings() 得到的目标 severity 取值列表（中英文混合）
    返回可用于 filter(severity__in=...) 的列表。
    """
    vals = list(sev_values)
    if rule.include_unknown_severity:
        vals = vals + ['', None]
    return vals


def _is_in_cooldown(event, now, cooldown_minutes):
    """判断事件是否处于冷却期（上次推送后尚未超过冷却时长）。"""
    if not event.last_notified_at:
        return False
    return now - event.last_notified_at < timedelta(minutes=cooldown_minutes)


def run_converge_scan(rule, sev_values, trigger='manual'):
    """执行一次带收敛的告警扫描。

    返回 (AlertRecord, detail_dict)
    sev_values: 当前阈值对应的 WAF/FW severity 取值列表
    """
    from apps.cmdb.models import WafAttackLog, VscanVuln, VscanWebVuln, AlertEvent, AlertRecord
    from apps.cmdb.api.security_alert_views import _WEB_THR

    now = timezone.now()
    ws = now - timedelta(minutes=rule.window_minutes)
    sev_for_filter = severity_queryset_values(rule, None, sev_values)

    # ---------- 1. 时间窗内的原始计数（保留原有语义） ----------
    waf_qs = WafAttackLog.objects.filter(
        device_type='WAF', log_time__gte=ws, severity__in=sev_for_filter)
    fw_qs = WafAttackLog.objects.filter(
        device_type='Firewall', log_time__gte=ws, severity__in=sev_for_filter)
    waf_new = waf_qs.count()
    fw_new = fw_qs.count()
    vuln_high = VscanVuln.objects.filter(severity__gte=VULN_HIGH_SEVERITY_MIN).count()
    # 运行时自检：标度反转的启发式信号（高危数不应超过总量的一半）
    _vuln_total = VscanVuln.objects.count()
    if _vuln_total and vuln_high * 2 > _vuln_total:
        logger.warning(
            'VscanVuln 高危占比异常(%.0f%%)，疑似 severity 标度反转，请核对 VULN_HIGH_SEVERITY_MIN',
            vuln_high * 100.0 / _vuln_total)
    web_thr = _WEB_THR.get(rule.severity_threshold, 0)
    web_high = VscanWebVuln.objects.filter(severity__lte=web_thr).count()
    total_new = waf_new + fw_new

    # ---------- 2. 指纹聚合：把窗口内日志聚合成事件维度 ----------
    # 只取需要的字段，避免整行加载；同指纹合并计数
    agg = {}
    for source, qs in (('WAF', waf_qs), ('Firewall', fw_qs)):
        for r in qs.values('event_type', 'src_ip', 'dst_ip', 'severity'):
            fp = make_fingerprint(source, r.get('event_type'), r.get('src_ip'), r.get('dst_ip'))
            item = agg.get(fp)
            if item is None:
                agg[fp] = {
                    'source': source,
                    'event_type': r.get('event_type') or '',
                    'src_ip': r.get('src_ip') or '',
                    'dst_ip': r.get('dst_ip') or '',
                    'severity': r.get('severity') or UNKNOWN_SEVERITY,
                    'count': 1,
                }
            else:
                item['count'] += 1

    # ---------- 3. 逐事件走状态机 ----------
    events_new = 0
    events_recurred = 0
    events_suppressed = 0
    to_notify = []          # 本次需要推送的事件（含新增与超冷却复现）

    for fp, info in agg.items():
        try:
            event = AlertEvent.objects.get(fingerprint=fp)
            created = False
        except AlertEvent.DoesNotExist:
            event = AlertEvent(
                fingerprint=fp,
                source=info['source'],
                event_type=info['event_type'],
                src_ip=info['src_ip'],
                dst_ip=info['dst_ip'],
                severity=info['severity'],
                status='firing',
                occurrence=0,
            )
            created = True

        # 已被运营动作（确认/忽略）的事件：仅更新 last_seen，不推送
        if not created and event.status in ('acked', 'suppressed'):
            event.occurrence += info['count']
            event.last_seen = now
            event.save(update_fields=['occurrence', 'last_seen'])
            events_recurred += 1
            continue

        # resolved 事件再次出现 → 重新打开为 firing（告警复发）
        if not created and event.status == 'resolved':
            event.status = 'firing'
            event.resolved_at = None
            event.occurrence = 0
            logger.info('alert event reopened: fp=%s', fp)

        event.occurrence += info['count']
        event.last_seen = now
        # 更新 severity 展示值（可能由空变为具体值）
        if info['severity'] and info['severity'] != UNKNOWN_SEVERITY:
            event.severity = info['severity']

        if created:
            events_new += 1
            event.save()
            to_notify.append((event, 'new'))
        else:
            events_recurred += 1
            if _is_in_cooldown(event, now, rule.cooldown_minutes):
                events_suppressed += 1
                event.save()
            else:
                event.save()
                to_notify.append((event, 'recur'))

    # ---------- 4. 恢复检测：超过 resolve_after 未复现 → resolved ----------
    events_resolved = 0
    resolved_list = []
    resolve_before = now - timedelta(minutes=rule.resolve_after_minutes)
    stale = AlertEvent.objects.filter(
        status__in=['firing', 'acked'],
        last_seen__lt=resolve_before,
    )
    for ev in stale:
        ev.status = 'resolved'
        ev.resolved_at = now
        ev.save(update_fields=['status', 'resolved_at'])
        events_resolved += 1
        resolved_list.append(ev)

    # ---------- 5. 落扫描记录 ----------
    detail = {
        'top_events': [
            {
                'fingerprint': fp[:12],
                'source': i['source'],
                'event_type': i['event_type'],
                'src_ip': i['src_ip'],
                'dst_ip': i['dst_ip'],
                'window_count': i['count'],
            }
            for fp, i in sorted(agg.items(), key=lambda kv: -kv[1]['count'])[:10]
        ],
        'vuln_high': vuln_high,
        'web_high': web_high,
        'resolved': [
            {
                'fingerprint': e.fingerprint[:12],
                'source': e.source,
                'event_type': e.event_type,
                'src_ip': e.src_ip,
                'occurrence': e.occurrence,
            }
            for e in resolved_list[:10]
        ],
    }

    rec = AlertRecord(
        trigger=trigger,
        window_start=ws,
        window_minutes=rule.window_minutes,
        severity_threshold=rule.severity_threshold,
        waf_new=waf_new, fw_new=fw_new,
        vuln_high=vuln_high, web_high=web_high,
        total_new=total_new,
        events_new=events_new,
        events_recurred=events_recurred,
        events_resolved=events_resolved,
        events_suppressed=events_suppressed,
        detail=_dump(detail),
    )

    # ---------- 6. 推送（触发通知 + 恢复通知） ----------
    channels = []
    if rule.enabled:
        if to_notify:
            from .alert_notify import notify_firing
            channels = notify_firing(rule, rec, to_notify, detail, now)
        if rule.notify_on_resolve and resolved_list:
            from .alert_notify import notify_resolved
            ch2 = notify_resolved(rule, resolved_list, now)
            for c in ch2:
                if c not in channels:
                    channels.append(c)

        # 回写"最后发声时间"：与通道成败解耦。
        # 冷却表达的是"系统就该事件发声的节奏"，若仅在推送成功时回写，
        # 则未配置通道时 last_notified_at 永远为空 → 冷却机制完全失效（2026-08-28 修复）。
        for ev, _kind in to_notify:
            ev.last_notified_at = now
            ev.notify_count = (ev.notify_count or 0) + 1
            ev.save(update_fields=['last_notified_at', 'notify_count'])

    rec.notified = bool(channels)
    rec.channels = ','.join(channels)
    rec.save()

    return rec, detail


def _dump(obj):
    import json
    return json.dumps(obj, ensure_ascii=False, default=str)


def event_stats():
    """事件中心统计卡数据。"""
    from apps.cmdb.models import AlertEvent
    qs = AlertEvent.objects.all()
    return {
        'firing': qs.filter(status='firing').count(),
        'acked': qs.filter(status='acked').count(),
        'resolved': qs.filter(status='resolved').count(),
        'suppressed': qs.filter(status='suppressed').count(),
        'total': qs.count(),
    }
