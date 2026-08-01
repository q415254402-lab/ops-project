#!/usr/bin/env python
"""
eSight 测试数据初始化脚本
"""
import os
import sys
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'settings')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
django.setup()

from django.utils import timezone
from apps.cmdb.models import (
    Manufacturer, DeviceType, DeviceModel, Device, Interface,
    Room, Cabinet, IPAddress, Vlan,
)
from apps.alarm.models import Alarm, AlarmDefinition, TrapRule, SyslogRule
from apps.performance.models import MetricDefinition, CollectTask, MetricThreshold
from apps.topology.models import TopologyMap
from apps.system.models import SystemParameter, DataDict

print('=== eSight 测试数据初始化 ===\n')

# 1. 厂商
print('[1/8] 创建厂商...')
manufacturers = {}
for name, code in [
    ('华为', 'huawei'), ('H3C', 'h3c'), ('锐捷', 'ruijie'),
    ('Cisco', 'cisco'), ('Dell', 'dell'), ('浪潮', 'inspur'),
    ('新华三', 'h3c_v2'), ('中兴', 'zte'),
]:
    obj, _ = Manufacturer.objects.get_or_create(code=code, defaults={'name': name})
    manufacturers[code] = obj
print(f'  ✅ {len(manufacturers)} 个厂商')

# 2. 设备类型
print('[2/8] 创建设备类型...')
device_types = {}
for name, code in [
    ('交换机', 'switch'), ('路由器', 'router'), ('防火墙', 'firewall'),
    ('服务器', 'server'), ('存储设备', 'storage'), ('虚拟机', 'vm'),
    ('无线AP', 'ap'), ('中间件', 'middleware'), ('数据库', 'database'),
    ('UPS', 'ups'), ('负载均衡', 'lb'),
]:
    obj, _ = DeviceType.objects.get_or_create(code=code, defaults={'name': name})
    device_types[code] = obj
print(f'  ✅ {len(device_types)} 种设备类型')

# 3. 设备型号
print('[3/8] 创建设备型号...')
models_data = [
    ('huawei', 'S5735-L48T4X', 'switch'),
    ('huawei', 'S6730-H48X6C', 'switch'),
    ('huawei', 'AR6280', 'router'),
    ('huawei', 'USG6555E', 'firewall'),
    ('h3c', 'S6520X-30QC-SI', 'switch'),
    ('h3c', 'MSR3620', 'router'),
    ('dell', 'PowerEdge R750', 'server'),
    ('inspur', 'NF5280M6', 'server'),
    ('cisco', 'Catalyst 9300', 'switch'),
]
device_models = {}
for mfr_code, model_name, type_code in models_data:
    obj, _ = DeviceModel.objects.get_or_create(
        manufacturer=manufacturers[mfr_code],
        name=model_name,
        defaults={'device_type': device_types[type_code]},
    )
    device_models[f'{mfr_code}_{model_name}'] = obj
print(f'  ✅ {len(device_models)} 个型号')

# 4. 机房和机柜
print('[4/8] 创建机房/机柜...')
room1, _ = Room.objects.get_or_create(
    code='bj-dc01', defaults={
        'name': '北京数据中心01', 'address': '北京市海淀区',
        'area': '华北区', 'floor': '3F',
        'temperature': 22.5, 'humidity': 45.0,
    }
)
room2, _ = Room.objects.get_or_create(
    code='sh-dc01', defaults={
        'name': '上海数据中心01', 'address': '上海市浦东新区',
        'area': '华东区', 'floor': '5F',
        'temperature': 23.0, 'humidity': 42.0,
    }
)
cabinet1, _ = Cabinet.objects.get_or_create(
    room=room1, code='A01', defaults={
        'name': 'A列01柜', 'total_u': 42, 'used_u': 28,
        'power_capacity_kw': 10.0, 'current_power_kw': 6.5,
    }
)
cabinet2, _ = Cabinet.objects.get_or_create(
    room=room1, code='A02', defaults={
        'name': 'A列02柜', 'total_u': 42, 'used_u': 15,
        'power_capacity_kw': 10.0, 'current_power_kw': 3.2,
    }
)
print(f'  ✅ 2 个机房, 2 个机柜')

# 5. 设备
print('[5/8] 创建设备...')
devices_data = [
    {'name': 'CORE-SW-01', 'ip': '10.1.1.1', 'type': 'switch', 'mfr': 'huawei', 'model': 'S6730-H48X6C', 'room': room1, 'cabinet': cabinet1, 'status': 'online'},
    {'name': 'CORE-SW-02', 'ip': '10.1.1.2', 'type': 'switch', 'mfr': 'huawei', 'model': 'S6730-H48X6C', 'room': room1, 'cabinet': cabinet1, 'status': 'online'},
    {'name': 'ACC-SW-01', 'ip': '10.1.2.1', 'type': 'switch', 'mfr': 'huawei', 'model': 'S5735-L48T4X', 'room': room1, 'cabinet': cabinet2, 'status': 'online'},
    {'name': 'ACC-SW-02', 'ip': '10.1.2.2', 'type': 'switch', 'mfr': 'h3c', 'model': 'S6520X-30QC-SI', 'room': room1, 'cabinet': cabinet2, 'status': 'online'},
    {'name': 'ROUTER-01', 'ip': '10.1.0.1', 'type': 'router', 'mfr': 'huawei', 'model': 'AR6280', 'room': room1, 'cabinet': cabinet1, 'status': 'online'},
    {'name': 'FW-01', 'ip': '10.1.0.254', 'type': 'firewall', 'mfr': 'huawei', 'model': 'USG6555E', 'room': room1, 'cabinet': cabinet1, 'status': 'online'},
    {'name': 'SRV-DB-01', 'ip': '10.2.1.1', 'type': 'server', 'mfr': 'dell', 'model': 'PowerEdge R750', 'room': room1, 'cabinet': cabinet2, 'status': 'online'},
    {'name': 'SRV-DB-02', 'ip': '10.2.1.2', 'type': 'server', 'mfr': 'dell', 'model': 'PowerEdge R750', 'room': room1, 'cabinet': cabinet2, 'status': 'online'},
    {'name': 'SRV-APP-01', 'ip': '10.2.2.1', 'type': 'server', 'mfr': 'inspur', 'model': 'NF5280M6', 'room': room2, 'cabinet': None, 'status': 'online'},
    {'name': 'SRV-APP-02', 'ip': '10.2.2.2', 'type': 'server', 'mfr': 'inspur', 'model': 'NF5280M6', 'room': room2, 'cabinet': None, 'status': 'offline'},
    {'name': 'SRV-WEB-01', 'ip': '10.2.3.1', 'type': 'server', 'mfr': 'dell', 'model': 'PowerEdge R750', 'room': room2, 'cabinet': None, 'status': 'online'},
    {'name': 'ACC-SW-BJ-03', 'ip': '10.1.2.3', 'type': 'switch', 'mfr': 'cisco', 'model': 'Catalyst 9300', 'room': room1, 'cabinet': cabinet2, 'status': 'maintenance'},
    {'name': 'ROUTER-SH-01', 'ip': '10.3.0.1', 'type': 'router', 'mfr': 'h3c', 'model': 'MSR3620', 'room': room2, 'cabinet': None, 'status': 'online'},
]
devices = {}
for d in devices_data:
    mfr_key = d['mfr']
    model_key = f"{d['mfr']}_{d['model']}"
    obj, created = Device.objects.get_or_create(
        ip_address=d['ip'],
        defaults={
            'name': d['name'],
            'hostname': d['name'].lower(),
            'device_type': device_types[d['type']],
            'device_model': device_models.get(model_key),
            'manufacturer': manufacturers.get(mfr_key),
            'status': d['status'],
            'room': d.get('room'),
            'cabinet': d.get('cabinet'),
            'last_seen_at': timezone.now() if d['status'] == 'online' else None,
        }
    )
    devices[d['name']] = obj
print(f'  ✅ {len(devices)} 台设备')

# 6. 接口
print('[6/8] 创建网络接口...')
iface_count = 0
for dev_name, device in devices.items():
    if device.device_type.code in ('switch', 'router', 'firewall'):
        for i in range(1, 5):
            Interface.objects.get_or_create(
                device=device, name=f'GE0/0/{i}',
                defaults={
                    'index': i,
                    'if_type': 'physical',
                    'status': 'up',
                    'speed': 1000000000,
                    'in_octets': 1024 * 1024 * (i * 100),
                    'out_octets': 1024 * 1024 * (i * 80),
                }
            )
            iface_count += 1
print(f'  ✅ {iface_count} 个接口')

# 7. 告警定义
print('[7/8] 创建告警定义...')
alarm_defs = [
    {'name': '设备离线', 'code': 'device_offline', 'severity': 'major', 'source': 'polling'},
    {'name': 'CPU 使用率过高', 'code': 'cpu_high', 'severity': 'warning', 'source': 'threshold'},
    {'name': '内存使用率过高', 'code': 'memory_high', 'severity': 'warning', 'source': 'threshold'},
    {'name': '接口 Down', 'code': 'interface_down', 'severity': 'minor', 'source': 'trap'},
    {'name': '电源故障', 'code': 'power_failure', 'severity': 'critical', 'source': 'trap'},
    {'name': '风扇故障', 'code': 'fan_failure', 'severity': 'major', 'source': 'trap'},
    {'name': '温度过高', 'code': 'temperature_high', 'severity': 'critical', 'source': 'trap'},
    {'name': '配置变更', 'code': 'config_change', 'severity': 'info', 'source': 'syslog'},
]
for ad in alarm_defs:
    AlarmDefinition.objects.get_or_create(code=ad['code'], defaults=ad)
print(f'  ✅ {len(alarm_defs)} 个告警定义')

# 创建一些示例告警
now = timezone.now()
sample_alarms = [
    {'device': devices['SRV-APP-02'], 'severity': 'critical', 'title': '设备离线: SRV-APP-02 (10.2.2.2)', 'status': 'active'},
    {'device': devices['ACC-SW-BJ-03'], 'severity': 'warning', 'title': 'CPU 使用率过高: ACC-SW-BJ-03 = 92%', 'status': 'active'},
    {'device': devices['CORE-SW-01'], 'severity': 'minor', 'title': '接口 Down: GE0/0/3', 'status': 'acknowledged'},
    {'device': devices['FW-01'], 'severity': 'critical', 'title': '温度过高: FW-01 = 78℃', 'status': 'active'},
    {'device': devices['SRV-DB-01'], 'severity': 'warning', 'title': '内存使用率过高: SRV-DB-01 = 89%', 'status': 'active'},
]
for sa in sample_alarms:
    Alarm.objects.get_or_create(
        device=sa['device'], title=sa['title'],
        defaults={
            'severity': sa['severity'],
            'status': sa['status'],
            'first_occurred_at': now - timezone.timedelta(hours=2),
            'last_occurred_at': now,
        }
    )
print(f'  ✅ {len(sample_alarms)} 条示例告警')

# 8. 性能指标定义
print('[8/8] 创建性能指标...')
metrics = [
    {'name': 'CPU 使用率', 'code': 'cpu_usage', 'unit': '%', 'type': 'server', 'method': 'ssh'},
    {'name': '内存使用率', 'code': 'memory_usage', 'unit': '%', 'type': 'server', 'method': 'ssh'},
    {'name': 'CPU 使用率', 'code': 'cpu_usage_snmp', 'unit': '%', 'type': 'switch', 'method': 'snmp', 'oid': '1.3.6.1.4.1.2011.5.25.31.1.1.1.1.5'},
    {'name': '内存使用率', 'code': 'memory_usage_snmp', 'unit': '%', 'type': 'switch', 'method': 'snmp', 'oid': '1.3.6.1.4.1.2011.5.25.31.1.1.1.1.7'},
    {'name': 'Ping 延迟', 'code': 'ping_rtt', 'unit': 'ms', 'type': 'server', 'method': 'ping'},
    {'name': 'Ping 丢包率', 'code': 'ping_loss', 'unit': '%', 'type': 'server', 'method': 'ping'},
]
for m in metrics:
    MetricDefinition.objects.get_or_create(
        code=m['code'],
        defaults={
            'name': m['name'],
            'unit': m['unit'],
            'device_type': device_types[m['type']],
            'collection_method': m['method'],
            'oid': m.get('oid', ''),
        }
    )
print(f'  ✅ {len(metrics)} 个指标定义')

# 系统参数
params = [
    ('general', 'site_name', 'eSight 统一运维管理系统', 'string'),
    ('general', 'timezone', 'Asia/Shanghai', 'string'),
    ('alarm', 'auto_clear_timeout', '3600', 'int'),
    ('alarm', 'compress_window', '300', 'int'),
    ('collection', 'default_snmp_community', 'public', 'string'),
    ('collection', 'default_interval', '300', 'int'),
]
for cat, key, val, vtype in params:
    SystemParameter.objects.get_or_create(key=key, defaults={
        'category': cat, 'value': val, 'value_type': vtype,
    })

print(f'\n=== 初始化完成 ===')
print(f'厂商: {Manufacturer.objects.count()}')
print(f'设备类型: {DeviceType.objects.count()}')
print(f'设备型号: {DeviceModel.objects.count()}')
print(f'机房: {Room.objects.count()}')
print(f'机柜: {Cabinet.objects.count()}')
print(f'设备: {Device.objects.count()}')
print(f'接口: {Interface.objects.count()}')
print(f'告警定义: {AlarmDefinition.objects.count()}')
print(f'活跃告警: {Alarm.objects.filter(status="active").count()}')
print(f'性能指标: {MetricDefinition.objects.count()}')
