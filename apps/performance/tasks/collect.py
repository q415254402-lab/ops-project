"""
性能数据采集 Celery 任务
"""
import logging
from celery import shared_task
from django.db.models import Q
from django.utils import timezone

from apps.performance import models

logger = logging.getLogger('esight.performance')


@shared_task(bind=True, max_retries=2, default_retry_delay=30)
def collect_metric_data(self, task_id):
    """执行采集任务"""
    from apps.performance.models import CollectTask, MetricData
    from apps.cmdb.models import Device
    from collectors import SNMPCollector, SSHCollector

    task = CollectTask.objects.get(id=task_id)
    if not task.enabled:
        return

    logger.info(f'开始执行采集任务: {task.name}')
    task.status = 'running'
    task.last_run_at = timezone.now()
    task.save(update_fields=['status', 'last_run_at'])

    metrics = task.metrics.filter(enabled=True)
    devices = task.devices.filter(status='online')
    now = timezone.now()

    success_count = 0
    error_count = 0

    for device in devices:
        for metric in metrics:
            try:
                value = _collect_single_metric(device, metric)
                if value is not None:
                    MetricData.objects.create(
                        device=device,
                        metric=metric,
                        value=value,
                        timestamp=now,
                    )
                    # 检查阈值
                    _check_threshold(device, metric, value)
                    success_count += 1
            except Exception as e:
                error_count += 1
                logger.error(f'采集失败: {device.name} - {metric.code}: {e}')

    task.status = 'running' if error_count == 0 else 'error'
    task.last_error = f'{error_count} 个采集失败' if error_count > 0 else ''
    task.save(update_fields=['status', 'last_error'])
    logger.info(f'采集任务完成: {task.name}, 成功={success_count}, 失败={error_count}')


def _collect_single_metric(device, metric):
    """采集单个指标"""
    from collectors import SNMPCollector, SSHCollector

    if metric.collection_method == 'snmp':
        with SNMPCollector(device.ip_address, device.credential) as collector:
            if metric.oid:
                result = collector.get_custom_oid(metric.oid)
                return float(result) if result is not None else None
            # 内置指标
            if metric.code == 'cpu_usage':
                usages = collector.get_cpu_usage()
                return usages[0] if usages else None
            elif metric.code == 'memory_usage':
                usages = collector.get_memory_usage()
                return usages[0] if usages else None

    elif metric.collection_method == 'ssh':
        with SSHCollector(device.ip_address, device.credential) as collector:
            if metric.code == 'cpu_usage':
                info = collector.get_cpu_info()
                return info.get('usage_percent')
            elif metric.code == 'memory_usage':
                info = collector.get_memory_info()
                return info.get('usage_percent')
            elif metric.command:
                result = collector.get_custom_command(metric.command)
                if metric.parse_regex:
                    import re
                    match = re.search(metric.parse_regex, result['output'])
                    if match:
                        return float(match.group(1))
                return None

    elif metric.collection_method == 'ping':
        from collectors.ping_check import ping_latency
        result = ping_latency(device.ip_address)
        if result:
            if metric.code == 'ping_rtt':
                return result['avg']
            elif metric.code == 'ping_loss':
                return result['loss']
    return None


def _check_threshold(device, metric, value):
    """检查阈值并触发告警"""
    from apps.performance.models import MetricThreshold
    from apps.alarm.models import Alarm

    thresholds = MetricThreshold.objects.filter(
        metric=metric,
        enabled=True,
    ).filter(
        Q(device=device) | Q(device__isnull=True)
    )

    for threshold in thresholds:
        triggered = False
        if threshold.max_value is not None and value > threshold.max_value:
            triggered = True
        if threshold.min_value is not None and value < threshold.min_value:
            triggered = True

        if triggered:
            Alarm.objects.create(
                device=device,
                severity=threshold.level,
                title=f'{metric.name} 阈值告警: {device.name} = {value}{metric.unit}',
                detail=f'指标: {metric.name}, 当前值: {value}{metric.unit}, 阈值等级: {threshold.get_level_display()}',
                source_ip=device.ip_address,
                first_occurred_at=timezone.now(),
                last_occurred_at=timezone.now(),
            )
            logger.warning(f'阈值告警触发: {device.name} - {metric.name} = {value}')


@shared_task
def run_all_collect_tasks():
    """运行所有启用的采集任务（由 Celery Beat 定时调用）"""
    from apps.performance.models import CollectTask
    tasks = CollectTask.objects.filter(enabled=True)
    for task in tasks:
        collect_metric_data.delay(task.id)
    logger.info(f'已触发 {tasks.count()} 个采集任务')
