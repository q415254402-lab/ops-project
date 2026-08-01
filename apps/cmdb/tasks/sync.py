"""
CMDB 设备同步 Celery 任务
"""
import logging
from celery import shared_task
from django.utils import timezone

logger = logging.getLogger('esight.cmdb')


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def sync_device_info(self, device_id):
    """同步单个设备信息"""
    from apps.cmdb.models import Device
    from collectors import SNMPCollector, SSHCollector

    device = Device.objects.get(id=device_id)
    logger.info(f'开始同步设备: {device.name} ({device.ip_address})')

    try:
        if device.credential and device.credential.protocol.startswith('snmp'):
            _sync_via_snmp(device)
        elif device.credential and device.credential.protocol == 'ssh':
            _sync_via_ssh(device)
        else:
            logger.warning(f'设备 {device.name} 无有效凭据，跳过同步')
            return

        device.last_sync_at = timezone.now()
        device.last_seen_at = timezone.now()
        device.status = 'online'
        device.save(update_fields=['last_sync_at', 'last_seen_at', 'status'])
        logger.info(f'设备同步完成: {device.name}')

    except Exception as e:
        logger.error(f'设备同步失败: {device.name} - {e}')
        device.status = 'offline'
        device.save(update_fields=['status'])
        raise self.retry(exc=e)


@shared_task
def sync_all_devices():
    """同步所有设备"""
    from apps.cmdb.models import Device
    devices = Device.objects.filter(status__in=['online', 'offline'], manage_type='auto')
    for device in devices:
        sync_device_info.delay(device.id)
    logger.info(f'已触发 {devices.count()} 个设备的同步任务')


@shared_task
def sync_devices():
    """根据最后在线时间刷新设备状态（在线/离线）。

    设备最近 N 分钟内有 last_seen_at 则标记为 online，否则 offline；
    已退役 / 维护中的设备不参与状态翻转，仅刷新 last_sync_at。
    提供给 Celery Beat 定时调用（config/default.py CELERY_BEAT_SCHEDULE）。
    """
    from datetime import timedelta

    from django.utils import timezone

    from apps.cmdb.models import Device

    now = timezone.now()
    online_threshold = now - timedelta(minutes=5)

    online_ids = []
    offline_ids = []
    for device in Device.objects.exclude(status__in=['decommissioned', 'maintenance']):
        if device.last_seen_at and device.last_seen_at >= online_threshold:
            online_ids.append(device.id)
        else:
            offline_ids.append(device.id)

    if online_ids:
        Device.objects.filter(id__in=online_ids).update(status='online', last_sync_at=now)
    if offline_ids:
        Device.objects.filter(id__in=offline_ids).update(status='offline', last_sync_at=now)

    return {'online': len(online_ids), 'offline': len(offline_ids)}


def _sync_via_snmp(device):
    """通过 SNMP 同步设备"""
    from apps.cmdb.models import Interface
    from collectors import SNMPCollector

    with SNMPCollector(device.ip_address, device.credential) as collector:
        # 同步系统信息
        sys_info = collector.get_system_info()
        if sys_info:
            device.hostname = sys_info.get('sysname', device.hostname)
            device.description = sys_info.get('sysdescr', '')

        # 同步接口信息
        interfaces = collector.get_interfaces()
        for iface_data in interfaces:
            Interface.objects.update_or_create(
                device=device,
                name=iface_data['name'],
                defaults={
                    'index': iface_data['index'],
                    'speed': iface_data['speed'],
                    'status': iface_data['oper_status'],
                    'admin_status': iface_data['admin_status'] == 1,
                    'mac_address': iface_data['mac_address'],
                    'in_octets': iface_data['in_octets'],
                    'out_octets': iface_data['out_octets'],
                    'in_errors': iface_data['in_errors'],
                    'out_errors': iface_data['out_errors'],
                    'last_sync_at': timezone.now(),
                }
            )
        device.save()


def _sync_via_ssh(device):
    """通过 SSH 同步设备（服务器）"""
    from apps.cmdb.models import Server
    from collectors import SSHCollector

    with SSHCollector(device.ip_address, device.credential) as collector:
        sys_info = collector.get_system_info()
        if sys_info:
            device.hostname = sys_info.get('hostname', device.hostname)
            device.os_version = sys_info.get('os_version', '')

        # 同步服务器详情
        cpu_info = collector.get_cpu_info()
        mem_info = collector.get_memory_info()

        server, _ = Server.objects.get_or_create(device=device)
        if cpu_info:
            server.cpu_cores = cpu_info.get('cores', server.cpu_cores)
        if mem_info:
            server.memory_total_gb = mem_info.get('total_mb', 0) / 1024
        server.save()
        device.save()
