# -*- coding: utf-8 -*-
"""安全告警周期任务（Celery）——挂到 CELERY_BEAT_SCHEDULE 由 esight_beat 调度。

注意：
- esight_beat / esight_celery 已在 supervisord 中 RUNNING，无需新增基础设施。
- 任务需在 apps/cmdb/tasks/__init__.py 中 re-export，调度项用短名
  `apps.cmdb.tasks.alert_scan`（与既有 sync_devices 等保持一致）。
- 调度周期来自 AlertRule.scan_interval_minutes（数据库可配）；beat 以固定间隔触发本任务，
  任务内部再按规则判断是否到达执行时机，从而支持前端动态调整周期而无需重启 beat。
"""
import logging
from celery import shared_task
from django.utils import timezone

logger = logging.getLogger('app')

# beat 触发基准间隔（秒）。任务内部会按 AlertRule.scan_interval_minutes 做节流判断。
BEAT_TICK_SECONDS = 60


@shared_task(name='apps.cmdb.tasks.alert_scan', bind=True, max_retries=2, default_retry_delay=60)
def alert_scan(self):
    """定时执行安全告警扫描（带收敛 + 恢复检测）。

    节流逻辑：以 AlertRule.scan_interval_minutes 为准，若距上次扫描不足该间隔则跳过，
    这样前端改周期后无需重启 beat 即可生效。
    """
    try:
        from apps.cmdb.models import AlertRule
        from apps.cmdb.models_alert_engine import run_alert_scan_scheduled
    except ImportError as e:  # pragma: no cover
        logger.error('alert_scan import failed: %s', e)
        return {'ok': False, 'error': str(e)}

    try:
        rule, _ = AlertRule.objects.get_or_create(id=1)
    except Exception as e:
        logger.error('alert_scan: load rule failed: %s', e)
        return {'ok': False, 'error': 'load rule failed: %s' % e}

    if not rule.enabled:
        logger.info('alert_scan skipped: rule disabled')
        return {'ok': True, 'skipped': 'disabled'}

    interval = int(rule.scan_interval_minutes or 0)
    if interval <= 0:
        logger.info('alert_scan skipped: scan_interval_minutes=0 (manual only)')
        return {'ok': True, 'skipped': 'manual_only'}

    # 节流：距最近一次扫描不足间隔则跳过
    from apps.cmdb.models import AlertRecord
    from datetime import timedelta
    now = timezone.now()
    last = AlertRecord.objects.filter(trigger='scheduled').order_by('-scan_time').first()
    if last and last.scan_time and (now - last.scan_time) < timedelta(minutes=interval):
        logger.info('alert_scan throttled: last=%s interval=%dm', last.scan_time, interval)
        return {'ok': True, 'skipped': 'throttled'}

    try:
        rec, detail = run_alert_scan_scheduled(rule)
        logger.info('alert_scan done: new=%d recur=%d resolved=%d suppressed=%d notified=%s',
                    rec.events_new, rec.events_recurred,
                    rec.events_resolved, rec.events_suppressed, rec.notified)
        return {
            'ok': True,
            'record_id': rec.id,
            'events_new': rec.events_new,
            'events_resolved': rec.events_resolved,
            'events_suppressed': rec.events_suppressed,
            'notified': rec.notified,
            'channels': rec.channels,
        }
    except Exception as e:
        logger.error('alert_scan failed: %s', e)
        try:
            raise self.retry(exc=e)
        except Exception:
            return {'ok': False, 'error': str(e)}
