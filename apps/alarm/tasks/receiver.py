"""
告警接收处理任务 — Trap / Syslog
"""
import re
import json
import logging
from celery import shared_task
from django.utils import timezone

logger = logging.getLogger('esight.alarm')


@shared_task
def process_trap(trap_data):
    """处理 SNMP Trap"""
    from apps.alarm.models import TrapRule, Alarm, AlarmDefinition

    source_ip = trap_data.get('source_ip')
    oids = trap_data.get('oids', {})

    logger.info(f'收到 Trap: {source_ip} - {json.dumps(oids, ensure_ascii=False)[:200]}')

    # 匹配 Trap 规则
    trap_oid = oids.get('1.3.6.1.6.3.1.1.4.1.0', '')  # snmpTrapOID
    rules = TrapRule.objects.filter(enabled=True, oid=trap_oid)

    if not rules.exists():
        # 尝试模糊匹配
        rules = TrapRule.objects.filter(enabled=True, oid__icontains=trap_oid)

    for rule in rules:
        _create_alarm_from_trap(source_ip, oids, rule)
        return

    # 没有匹配规则，创建通用告警
    Alarm.objects.create(
        title=f'未识别 Trap: {source_ip}',
        detail=json.dumps(oids, ensure_ascii=False),
        severity='warning',
        source_ip=source_ip,
        raw_data=trap_data,
        first_occurred_at=timezone.now(),
        last_occurred_at=timezone.now(),
    )


def _create_alarm_from_trap(source_ip, oids, rule):
    """根据 Trap 规则创建告警"""
    from apps.alarm.models import Alarm
    from apps.cmdb.models import Device

    # 查找关联设备
    device = Device.objects.filter(ip_address=source_ip).first()

    # 渲染标题和详情
    title = _render_template(rule.title_template, oids) if rule.title_template else f'Trap: {rule.name}'
    detail = _render_template(rule.detail_template, oids) if rule.detail_template else json.dumps(oids, ensure_ascii=False)

    # 告警压缩：检查是否已存在相同活跃告警
    existing = Alarm.objects.filter(
        device=device,
        alarm_definition=rule.alarm_definition,
        status='active',
        last_occurred_at__gte=timezone.now() - timezone.timedelta(seconds=300),
    ).first()

    if existing:
        existing.occurrence_count += 1
        existing.last_occurred_at = timezone.now()
        existing.save(update_fields=['occurrence_count', 'last_occurred_at'])
        logger.info(f'告警压缩: {existing.title} (第 {existing.occurrence_count} 次)')
    else:
        Alarm.objects.create(
            alarm_definition=rule.alarm_definition,
            device=device,
            severity=rule.severity,
            title=title,
            detail=detail,
            source_ip=source_ip,
            raw_data=oids,
            first_occurred_at=timezone.now(),
            last_occurred_at=timezone.now(),
        )
        logger.info(f'新告警创建: {title}')


@shared_task
def process_syslog(message, source_ip):
    """处理 Syslog 消息"""
    from apps.alarm.models import SyslogRule, Alarm
    from apps.cmdb.models import Device

    logger.debug(f'收到 Syslog: {source_ip} - {message[:200]}')

    # 匹配 Syslog 规则
    rules = SyslogRule.objects.filter(enabled=True)
    for rule in rules:
        match = re.search(rule.pattern, message)
        if match:
            device = Device.objects.filter(ip_address=source_ip).first()
            severity = 'warning'
            if rule.severity_mapping:
                for level, patterns in rule.severity_mapping.items():
                    if any(p in message for p in patterns):
                        severity = level
                        break

            # 告警压缩
            existing = Alarm.objects.filter(
                device=device,
                alarm_definition=rule.alarm_definition,
                status='active',
                last_occurred_at__gte=timezone.now() - timezone.timedelta(seconds=300),
            ).first()

            if existing:
                existing.occurrence_count += 1
                existing.last_occurred_at = timezone.now()
                existing.save(update_fields=['occurrence_count', 'last_occurred_at'])
            else:
                Alarm.objects.create(
                    alarm_definition=rule.alarm_definition,
                    device=device,
                    severity=severity,
                    title=f'Syslog: {rule.name} - {source_ip}',
                    detail=message,
                    source_ip=source_ip,
                    first_occurred_at=timezone.now(),
                    last_occurred_at=timezone.now(),
                )
            return

    logger.debug(f'Syslog 消息未匹配任何规则: {source_ip}')


@shared_task
def check_device_status():
    """定期检查设备在线状态"""
    from apps.cmdb.models import Device
    from apps.alarm.models import Alarm
    from collectors.ping_check import ping_check

    devices = Device.objects.filter(manage_type='auto', status__in=['online', 'offline'])
    for device in devices:
        is_alive = ping_check(device.ip_address, timeout=3, count=2)

        if is_alive and device.status == 'offline':
            device.status = 'online'
            device.last_seen_at = timezone.now()
            device.save(update_fields=['status', 'last_seen_at'])
            # 清除离线告警
            Alarm.objects.filter(
                device=device,
                title__icontains='离线',
                status='active',
            ).update(status='cleared', cleared_at=timezone.now(), cleared_by='auto')
            logger.info(f'设备恢复在线: {device.name}')

        elif not is_alive and device.status == 'online':
            device.status = 'offline'
            device.save(update_fields=['status'])
            # 创建离线告警
            existing = Alarm.objects.filter(
                device=device,
                title__icontains='离线',
                status='active',
            ).first()
            if existing:
                existing.last_occurred_at = timezone.now()
                existing.occurrence_count += 1
                existing.save(update_fields=['last_occurred_at', 'occurrence_count'])
            else:
                Alarm.objects.create(
                    device=device,
                    severity='major',
                    title=f'设备离线: {device.name} ({device.ip_address})',
                    detail=f'设备 {device.name} ({device.ip_address}) 无法 Ping 通',
                    source_ip=device.ip_address,
                    first_occurred_at=timezone.now(),
                    last_occurred_at=timezone.now(),
                )
            logger.warning(f'设备离线: {device.name}')


def _render_template(template, data):
    """简单模板渲染"""
    result = template
    for key, value in data.items():
        result = result.replace(f'{{{key}}}', str(value))
    return result
