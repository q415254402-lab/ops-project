# -*- coding: utf-8 -*-
"""安全报表定时生成（Celery）

- gen_reports      ：beat 每小时触发，补齐"尚未生成的上一个完整周期"（day/week/month）
- backfill_reports ：回溯补生成历史周期，从【数据源最早日】到上一个完整周期，上限 max_periods
                     （2026-09-04：日报原来只有 1 份，用户要求最少显示 10 天 → 默认回填 30 天内）
- purge_reports    ：保留策略清理（日报 90 / 周报 104 / 月报永久）

时区统一用 Django localtime，避免依赖 beat 的 crontab 时区配置。
"""
import calendar
import logging
from datetime import timedelta
from django.utils import timezone
from celery import shared_task

logger = logging.getLogger('app__report')

# 保留策略：保留最近 N 份，None = 永久
RETENTION = {'day': 90, 'week': 104, 'month': None}

TITLE_MAP = {'day': '安全日报', 'week': '安全周报', 'month': '安全月报'}


def _add_months(d, n):
    """返回 d 加减 n 个月后的当月 1 号 00:00（n 可为负）"""
    total = (d.month - 1) + n
    y = d.year + total // 12
    m = total % 12 + 1
    return d.replace(year=y, month=m, day=1, hour=0, minute=0, second=0, microsecond=0)


def _midnight(d):
    return d.replace(hour=0, minute=0, second=0, microsecond=0)


def _last_period_bounds(period_type, now):
    """返回 (start, end, key) 上个完整周期的边界 + 周期键

    day  → 昨天 00:00 ~ 24:00, key=YYYY-MM-DD
    week → 上周一 ~ 上周日,   key=YYYY-Www
    month→ 上月1号 ~ 月末,    key=YYYY-MM
    """
    if period_type == 'day':
        yesterday = (now - timedelta(days=1))
        start = _midnight(yesterday)
        end = start + timedelta(days=1)
        key = start.strftime('%Y-%m-%d')
    elif period_type == 'week':
        this_monday = _midnight(now - timedelta(days=now.weekday()))
        end = this_monday
        start = end - timedelta(days=7)
        key = start.strftime('%G-W%V')
    else:  # month
        first_of_this = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        end = first_of_this
        last_day_prev = end - timedelta(days=1)
        start = last_day_prev.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        key = start.strftime('%Y-%m')
    return start, end, key


def _prev_bounds(period_type, start):
    """给定周期 start，返回其上一个同长度周期 (prev_start, prev_end)（环比用）"""
    if period_type == 'day':
        return start - timedelta(days=1), start
    if period_type == 'week':
        return start - timedelta(days=7), start
    p_end = start
    p_start = _add_months(start, -1)
    return p_start, p_end


def _earliest_source_date():
    """回填下界 = 主流量日志（WAF/防火墙）最早日。

    ⚠️ 2026-09-04 修正：不能把漏洞/告警的最早时间也算进来——
    VscanWebVuln.scan_time 最早到 2025-10，会把下界拉到一年前，
    生成一整年全 0 的空日报/空月报（max_periods 只能挡日报，挡不住月报）。
    日报/周报/月报的主体是 WAF/防火墙日志，用它的最早日作为"有意义的回填起点"。
    """
    from apps.cmdb.models import WafAttackLog
    try:
        obj = WafAttackLog.objects.order_by('log_time').first()
        if obj and obj.log_time:
            return timezone.localtime(obj.log_time)
    except Exception as e:
        logger.warning('backfill earliest probe WafAttackLog failed: %s', e)
    return None


def _iter_past_periods(period_type, now, count, floor=None):
    """从"上一个完整周期"往前迭代 count 个周期，yield (start, end, key, p_start, p_end)

    floor 为最早允许日期（datetime），早于它的周期不再产出。
    """
    start, end, key = _last_period_bounds(period_type, now)
    for _ in range(count):
        if floor is not None and start < floor:
            return
        p_start, p_end = _prev_bounds(period_type, start)
        yield start, end, key, p_start, p_end
        # 往前推一个周期
        end = start
        if period_type == 'day':
            start = start - timedelta(days=1)
            key = start.strftime('%Y-%m-%d')
        elif period_type == 'week':
            start = start - timedelta(days=7)
            key = start.strftime('%G-W%V')
        else:
            start = _add_months(start, -1)
            key = start.strftime('%Y-%m')


def _build_and_save(period_type, start, end, key, p_start, p_end, ai_summary=False):
    """生成并落库一份报表；已存在则跳过。

    ai_summary=True 时，落库后额外调 AI 总结引擎生成 data['summary']
    （周报/月报用；日报量大时效高，不占模型，由前端/规则引擎兜底）。
    返回 'created' / 'skipped'。
    """
    from apps.cmdb.models import SecurityReport
    from apps.cmdb.report.aggregate import build_report
    if SecurityReport.objects.filter(period_type=period_type, period_key=key).exists():
        return 'skipped'
    report_data = build_report(period_type, start, end, p_start, p_end)
    obj = SecurityReport(
        period_type=period_type, period_key=key,
        period_start=start, period_end=end,
        title='%s %s' % (TITLE_MAP[period_type], key),
    )
    obj.set_data(report_data)
    obj.save()
    # 周/月报落库后生成 AI 总结（失败自动降级规则引擎，不影响主流程）
    if ai_summary:
        try:
            from apps.cmdb.report.ai_summary import generate_summary_for_report
            summary, _ = generate_summary_for_report(obj)
            logger.info('gen_reports AI summary for %s/%s: engine=%s model=%s',
                        period_type, key,
                        (summary or {}).get('engine'), (summary or {}).get('model'))
        except Exception as e:
            logger.exception('AI summary gen failed for %s/%s: %s', period_type, key, e)
    return 'created'


@shared_task(name='apps.cmdb.tasks.gen_reports', bind=True, max_retries=2, default_retry_delay=120)
def gen_reports(self):
    """补齐"上一个完整周期"的三类报表（幂等）"""
    now = timezone.localtime(timezone.now())
    generated = []
    for pt in ('day', 'week', 'month'):
        try:
            start, end, key = _last_period_bounds(pt, now)
            p_start, p_end = _prev_bounds(pt, start)
        except Exception as e:
            logger.error('gen_reports %s bounds error: %s', pt, e)
            continue
        try:
            if _build_and_save(pt, start, end, key, p_start, p_end,
                               ai_summary=(pt in ('week', 'month'))) == 'created':
                generated.append('%s/%s' % (pt, key))
                logger.info('gen_reports generated %s/%s', pt, key)
        except Exception as e:
            logger.exception('gen_reports %s/%s failed: %s', pt, key, e)
    return {'ok': True, 'generated': generated}


@shared_task(name='apps.cmdb.tasks.regenerate_report_summary', bind=True, max_retries=1, default_retry_delay=60)
def regenerate_report_summary(self, period_type, period_key):
    """对已落库的周报/月报重新生成 AI 总结（用于模型修复后回填、或调整 prompt 后重算）。

    period_type 仅接受 week/month（日报走规则引擎，无需重算）。
    """
    from apps.cmdb.models import SecurityReport
    from apps.cmdb.report.ai_summary import generate_summary_for_report
    if period_type not in ('week', 'month'):
        return {'ok': False, 'error': '仅支持 week/month 重算 AI 总结'}
    try:
        obj = SecurityReport.objects.get(period_type=period_type, period_key=period_key)
    except SecurityReport.DoesNotExist:
        return {'ok': False, 'error': '报表不存在: %s/%s' % (period_type, period_key)}
    summary, changed = generate_summary_for_report(obj)
    logger.info('regenerate_report_summary %s/%s engine=%s model=%s',
                period_type, period_key,
                (summary or {}).get('engine'), (summary or {}).get('model'))
    return {'ok': True, 'changed': changed,
            'engine': (summary or {}).get('engine'), 'model': (summary or {}).get('model')}


@shared_task(name='apps.cmdb.tasks.backfill_reports', bind=True, max_retries=2, default_retry_delay=300)
def backfill_reports(self, period_type='day', max_periods=30):
    """回溯补生成历史报表

    从"上一个完整周期"往前补 max_periods 个周期，下界为【数据源最早日】
    （避免生成一堆全 0 的空日报）。已存在的跳过，幂等。
    """
    from apps.cmdb.report.aggregate import build_report  # noqa: F401  (确保依赖可用)
    now = timezone.localtime(timezone.now())
    floor = None
    earliest = _earliest_source_date()
    if earliest:
        if period_type == 'day':
            floor = _midnight(earliest)
        elif period_type == 'week':
            floor = _midnight(earliest - timedelta(days=earliest.weekday()))
        else:
            floor = earliest.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    created, skipped, failed = [], 0, []
    for start, end, key, p_start, p_end in _iter_past_periods(period_type, now, max_periods, floor):
        try:
            r = _build_and_save(period_type, start, end, key, p_start, p_end)
            if r == 'created':
                created.append(key)
            else:
                skipped += 1
        except Exception as e:
            failed.append('%s: %s' % (key, e))
            logger.exception('backfill %s/%s failed: %s', period_type, key, e)

    result = {
        'ok': not failed,
        'period_type': period_type,
        'floor': floor.strftime('%Y-%m-%d') if floor else None,
        'created': created,
        'skipped': skipped,
        'failed': failed,
    }
    logger.info('backfill_reports done: %s', result)
    return result


@shared_task(name='apps.cmdb.tasks.purge_reports', bind=True)
def purge_reports(self):
    """保留策略清理：日报 90 / 周报 104 / 月报永久"""
    from apps.cmdb.models import SecurityReport
    purged = {}
    for pt, keep in RETENTION.items():
        if keep is None:
            continue
        qs = SecurityReport.objects.filter(period_type=pt).order_by('-period_start')
        stale_ids = list(qs.values_list('id', flat=True)[keep:])
        if stale_ids:
            SecurityReport.objects.filter(id__in=stale_ids).delete()
            purged[pt] = len(stale_ids)
    logger.info('purge_reports purged: %s', purged)
    return {'ok': True, 'purged': purged}


@shared_task(name='apps.cmdb.tasks.backfill_day_summaries', bind=True, max_retries=1)
def backfill_day_summaries(self):
    """为所有【已落库但 data['summary'] 为空】的日报补算规则引擎总结并写回 DB。

    背景：日报量大时效高，生成时不调 AI；而历史日报是回填任务生成的，当时
    也没写 summary（只有当前日报在 /current/ 视图打开时现算）。导致历史日报
    归档详情打开没有"本期总结"。本任务用规则引擎一次性补齐存量，幂等。

    周/月报不受影响（生成时已写 AI summary）。
    """
    from apps.cmdb.models import SecurityReport
    from apps.cmdb.report.ai_summary import generate_summary

    filled, skipped, failed = [], 0, []
    qs = SecurityReport.objects.filter(period_type='day').order_by('-period_start')
    for obj in qs:
        data = obj.get_data() or {}
        if not data:
            skipped += 1
            continue
        summary = data.get('summary')
        if summary and summary.get('text'):
            skipped += 1  # 已有总结，跳过（幂等）
            continue
        try:
            s = generate_summary('day', data)
            data['summary'] = s
            obj.set_data(data)
            obj.save(update_fields=['data'])
            filled.append('%s[%s]' % (obj.period_key, (s or {}).get('engine')))
            logger.info('backfill_day_summaries filled %s engine=%s',
                        obj.period_key, (s or {}).get('engine'))
        except Exception as e:
            failed.append('%s: %s' % (obj.period_key, e))
            logger.exception('backfill_day_summaries %s failed: %s', obj.period_key, e)

    result = {'ok': not failed, 'filled': filled, 'skipped': skipped, 'failed': failed}
    logger.info('backfill_day_summaries done: filled=%d skipped=%d failed=%d',
                len(filled), skipped, len(failed))
    return result
