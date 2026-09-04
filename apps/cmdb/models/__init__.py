from .base import Manufacturer, Credential
from .device import DeviceType, DeviceModel, Device, Interface
from .network import Vlan, IPAddress, MacAddress
from .server import Server, CPUMetric, MemoryMetric, DiskMetric
from .datacenter import Room, Cabinet, UPS, PDU
from .software import Software, License
# v2 完全复刻 control 网络设备模块（本地落库）
from .control_models import (
    ControllerAdmin, NetworkGroupModel, EquipmentTypeCMDBModel,
    NetworkEquipmentModel, NetworkBackupGroupModel, NetworkBackupModel,
    NetworkBackupTaskModel, NetworkEquipmentLogModel,
    NetworkSnmpInfoModel, NetworkInterfaceInfoModel, NetworkIpInfoModel,
    NetworkConfigModel,
)
# v2 IP 地址管理模块（本地落库）
from .ip_management import (
    IpSubnetManagerGroupModel, IpSubnetManagerModel, IpAddressModel,
    IpManagerScanLogModel,
)
# v2 WAF 安全日志（syslog 接收）
from .waf_security import WafAttackLog
# v3 vScan WEB 漏洞落库（2026-08-22）
from .vscan_web import VscanWebTask, VscanWebSite, VscanWebVuln
# v3 vScan 系统漏洞落库（2026-08-26，复用 WEB 模式）
from .vscan_sys import VscanVuln
# v7 安全告警（2026-08-28，规则配置 + 扫描记录）
from .security_alert import AlertRule, AlertRecord, AlertEvent
# v8 安全报表（日/周/月报落库，2026-09-03）
from .security_report import SecurityReport

__all__ = [
    'Manufacturer', 'Credential',
    'DeviceType', 'DeviceModel', 'Device', 'Interface',
    'Vlan', 'IPAddress', 'MacAddress',
    'Server', 'CPUMetric', 'MemoryMetric', 'DiskMetric',
    'Room', 'Cabinet', 'UPS', 'PDU',
    'Software', 'License',
    # v2
    'ControllerAdmin', 'NetworkGroupModel', 'EquipmentTypeCMDBModel',
    'NetworkEquipmentModel', 'NetworkBackupGroupModel', 'NetworkBackupModel',
    'NetworkBackupTaskModel', 'NetworkEquipmentLogModel',
    'NetworkSnmpInfoModel', 'NetworkInterfaceInfoModel', 'NetworkIpInfoModel',
    'NetworkConfigModel',
    # v2 IP 管理
    'IpSubnetManagerGroupModel', 'IpSubnetManagerModel', 'IpAddressModel',
    'IpManagerScanLogModel',
    # v2 WAF 安全日志
    'WafAttackLog',
    # v3 vScan WEB 漏洞落库（2026-08-22）
    'VscanWebTask', 'VscanWebSite', 'VscanWebVuln',
    # v3 vScan 系统漏洞落库（2026-08-26）
    'VscanVuln',
    # v7 安全告警（2026-08-28）
    'AlertRule', 'AlertRecord',
    # v8 安全报表（2026-09-03）
    'SecurityReport',
]
