# -*- coding: utf-8 -*-
"""
自动发现 Celery 任务

任务复用 topology.DiscoveryTask 模型（避免重复建表）：
    - ip_ranges        : 扫描范围
    - protocols        : ['icmp', 'snmp', 'lldp']
    - credentials      : 尝试的凭据（M2M）
    - result           : {'hosts': [...], 'progress': {...}, 'summary': {...}}
    - discovered_count : 存活主机数
"""
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from celery import shared_task
from django.db import transaction
from django.utils import timezone

from apps.discovery.engine import expand_ip_ranges, probe_host

logger = logging.getLogger('esight.discovery')

# 并发扫描线程数（SNMP/ping 都是 IO 密集，可适当放大）
MAX_WORKERS = 32
# 每扫描多少台回写一次进度，避免频繁写库
PROGRESS_FLUSH_STEP = 20


@shared_task(bind=True)
def run_discovery_task(self, task_id, auto_import=False):
    """
    执行一次自动发现。

    :param task_id:     topology.DiscoveryTask 主键
    :param auto_import: 扫描完成后是否自动导入 CMDB
    """
    from apps.topology.models import DiscoveryTask

    try:
        task = DiscoveryTask.objects.get(id=task_id)
    except DiscoveryTask.DoesNotExist:
        logger.error('发现任务不存在: %s', task_id)
        return {'error': 'task not found'}

    task.status = 'running'
    task.started_at = timezone.now()
    task.error_message = ''
    task.save(update_fields=['status', 'started_at', 'error_message'])

    try:
        protocols = task.protocols or ['icmp', 'snmp']
        credentials = list(task.credentials.all())
        targets = expand_ip_ranges(task.ip_ranges)

        if not targets:
            raise ValueError('IP 范围为空或格式不合法')

        logger.info('发现任务 #%s 开始：%s 个目标，协议 %s', task_id, len(targets), protocols)

        hosts = []
        scanned = 0
        total = len(targets)

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            futures = {
                pool.submit(probe_host, ip, credentials, protocols): ip
                for ip in targets
            }
            for future in as_completed(futures):
                ip = futures[future]
                scanned += 1
                try:
                    record = future.result()
                except Exception as exc:
                    logger.warning('探测异常 %s: %s', ip, exc)
                    record = {'ip': ip, 'alive': False, 'snmp_ok': False, 'error': str(exc)[:200]}

                if record.get('alive'):
                    hosts.append(record)

                if scanned % PROGRESS_FLUSH_STEP == 0 or scanned == total:
                    _flush_progress(task, scanned, total, len(hosts))

        hosts.sort(key=lambda h: _ip_sort_key(h['ip']))
        summary = _build_summary(hosts)

        task.result = {
            'hosts': hosts,
            'progress': {'scanned': total, 'total': total, 'percent': 100},
            'summary': summary,
            'scanned_at': timezone.now().isoformat(),
        }
        task.discovered_count = len(hosts)
        task.status = 'completed'
        task.completed_at = timezone.now()
        task.save(update_fields=['result', 'discovered_count', 'status', 'completed_at'])

        logger.info('发现任务 #%s 完成：扫描 %s，存活 %s', task_id, total, len(hosts))

        if auto_import:
            import_discovered_devices.delay(task_id)

        return {'total': total, 'alive': len(hosts), 'summary': summary}

    except Exception as exc:
        logger.exception('发现任务 #%s 失败', task_id)
        task.status = 'failed'
        task.error_message = str(exc)[:1000]
        task.completed_at = timezone.now()
        task.save(update_fields=['status', 'error_message', 'completed_at'])
        raise


def _flush_progress(task, scanned, total, alive):
    """回写扫描进度（只更新 result 的 progress 段）"""
    result = task.result if isinstance(task.result, dict) else {}
    result['progress'] = {
        'scanned': scanned,
        'total': total,
        'alive': alive,
        'percent': round(scanned * 100.0 / total, 1) if total else 100,
    }
    task.result = result
    task.discovered_count = alive
    task.save(update_fields=['result', 'discovered_count'])


def _ip_sort_key(ip):
    """IP 字符串排序键"""
    try:
        import ipaddress
        return int(ipaddress.ip_address(ip))
    except Exception:
        return 0


def _build_summary(hosts):
    """按类型 / 厂商聚合统计"""
    by_type, by_vendor = {}, {}
    snmp_ok = 0
    for host in hosts:
        if host.get('snmp_ok'):
            snmp_ok += 1
        type_name = host.get('device_type_name') or '未知设备'
        vendor = host.get('vendor') or '未知厂商'
        by_type[type_name] = by_type.get(type_name, 0) + 1
        by_vendor[vendor] = by_vendor.get(vendor, 0) + 1
    return {
        'alive': len(hosts),
        'snmp_ok': snmp_ok,
        'by_type': by_type,
        'by_vendor': by_vendor,
    }


# ------------------------------------------------------------------ 导入 CMDB
@shared_task
def import_discovered_devices(task_id, only_ips=None):
    """
    将发现结果导入 CMDB。

    :param task_id:  发现任务 ID
    :param only_ips: 仅导入指定 IP（None 表示全部存活主机）
    :return: {'created': n, 'updated': n, 'skipped': n}
    """
    from apps.topology.models import DiscoveryTask

    task = DiscoveryTask.objects.get(id=task_id)
    hosts = (task.result or {}).get('hosts', [])
    if only_ips:
        wanted = set(only_ips)
        hosts = [h for h in hosts if h.get('ip') in wanted]

    stats = {'created': 0, 'updated': 0, 'skipped': 0, 'errors': []}
    for host in hosts:
        try:
            with transaction.atomic():
                action = _import_single_host(host, task)
            stats[action] += 1
        except Exception as exc:
            logger.warning('导入设备失败 %s: %s', host.get('ip'), exc)
            stats['skipped'] += 1
            stats['errors'].append(f"{host.get('ip')}: {str(exc)[:120]}")

    logger.info('发现任务 #%s 导入完成: %s', task_id, stats)
    return stats


def _import_single_host(host, task=None):
    """导入单台主机，返回 'created' / 'updated'"""
    from apps.cmdb.models import (
        Device, DeviceType, Interface, IPAddress, Manufacturer,
    )

    ip = host['ip']

    # 设备类型
    type_code = host.get('device_type') or 'unknown'
    device_type, _ = DeviceType.objects.get_or_create(
        code=type_code,
        defaults={
            'name': host.get('device_type_name') or '未知设备',
            'icon': host.get('icon') or '',
        },
    )

    # 厂商
    manufacturer = None
    vendor_code = host.get('vendor_code')
    if vendor_code and vendor_code != 'unknown':
        manufacturer, _ = Manufacturer.objects.get_or_create(
            code=vendor_code,
            defaults={'name': host.get('vendor') or vendor_code},
        )

    now = timezone.now()
    defaults = {
        'name': host.get('hostname') or ip,
        'hostname': host.get('hostname') or '',
        'device_type': device_type,
        'manufacturer': manufacturer,
        'os_version': host.get('os_version') or '',
        'mac_address': host.get('mac_address') or '',
        'description': (host.get('sysdescr') or '')[:1000],
        'status': 'online',
        'last_seen_at': now,
        'last_sync_at': now,
    }
    if host.get('credential_id'):
        defaults['credential_id'] = host['credential_id']

    device, created = Device.objects.get_or_create(
        ip_address=ip,
        defaults={**defaults, 'discovered_at': now, 'manage_type': 'auto'},
    )

    if not created:
        # 已存在：只补空字段和状态，不覆盖人工维护的名称
        device.status = 'online'
        device.last_seen_at = now
        device.last_sync_at = now
        if not device.hostname and defaults['hostname']:
            device.hostname = defaults['hostname']
        if not device.mac_address and defaults['mac_address']:
            device.mac_address = defaults['mac_address']
        if not device.os_version and defaults['os_version']:
            device.os_version = defaults['os_version']
        if not device.manufacturer_id and manufacturer:
            device.manufacturer = manufacturer
        if not device.credential_id and host.get('credential_id'):
            device.credential_id = host['credential_id']
        device.save()

    # 接口
    for iface in host.get('interfaces') or []:
        name = (iface.get('name') or '').strip()
        if not name:
            continue
        Interface.objects.update_or_create(
            device=device,
            name=name,
            defaults={
                'index': iface.get('index') or 0,
                'speed': iface.get('speed') or 0,
                'status': iface.get('oper_status') or 'unknown',
                'admin_status': iface.get('admin_status') == 1,
                'mac_address': iface.get('mac_address') or '',
                'in_octets': iface.get('in_octets') or 0,
                'out_octets': iface.get('out_octets') or 0,
                'in_errors': iface.get('in_errors') or 0,
                'out_errors': iface.get('out_errors') or 0,
                'last_sync_at': now,
            },
        )

    # LLDP 邻居写回接口（供拓扑构建使用）
    _save_lldp_to_interfaces(device, host.get('lldp_neighbors') or [])

    # IP 地址台账
    IPAddress.objects.update_or_create(
        address=ip,
        defaults={
            'subnet': _guess_subnet(ip),
            'device': device,
            'status': 'allocated',
            'hostname': host.get('hostname') or '',
            'last_seen_at': now,
        },
    )

    return 'created' if created else 'updated'


def _save_lldp_to_interfaces(device, neighbors):
    """把 LLDP 邻居信息写入本端接口字段"""
    from apps.cmdb.models import Interface

    if not neighbors:
        return
    local_ifaces = {i.name: i for i in device.interfaces.all()}
    for nb in neighbors:
        local_port = (nb.get('local_port') or '').strip()
        iface = local_ifaces.get(local_port)
        if iface is None:
            continue
        iface.lldp_remote_device = (nb.get('remote_system') or nb.get('remote_chassis') or '')[:128]
        iface.lldp_remote_port = (nb.get('remote_port') or '')[:128]
        iface.save(update_fields=['lldp_remote_device', 'lldp_remote_port'])
        _ = Interface  # 保持导入语义清晰


def _guess_subnet(ip):
    """无子网信息时按 /24 归并"""
    try:
        import ipaddress
        net = ipaddress.ip_network(f'{ip}/24', strict=False)
        return str(net)
    except Exception:
        return ''


# ------------------------------------------------------------------ 周期任务
@shared_task
def scheduled_discovery():
    """执行所有到期的计划发现任务（由 celery beat 调度）"""
    from apps.topology.models import DiscoveryTask

    now = timezone.now()
    pending = DiscoveryTask.objects.filter(
        status='pending',
        scheduled_at__isnull=False,
        scheduled_at__lte=now,
    )
    count = 0
    for task in pending:
        run_discovery_task.delay(task.id)
        count += 1
    if count:
        logger.info('已触发 %s 个计划发现任务', count)
    return count
