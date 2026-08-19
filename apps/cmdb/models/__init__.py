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
]
