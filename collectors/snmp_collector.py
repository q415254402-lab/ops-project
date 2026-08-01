"""
SNMP 采集器 — 支持 SNMPv1/v2c/v3
用于设备信息采集、性能数据采集、接口信息采集
"""
import logging
from pysnmp.hlapi import (
    getCmd, nextCmd, bulkCmd,
    SnmpEngine, CommunityData, UsmUserData,
    UdpTransportTarget, ContextData,
    ObjectType, ObjectIdentity,
    usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol,
    usmDESPrivProtocol, usmAesCfb128Protocol,
    usmNoAuthProtocol, usmNoPrivProtocol,
)

from .base import BaseCollector

logger = logging.getLogger('esight.collector.snmp')

# 常用 OID
OIDS = {
    # System MIB
    'sysDescr': '1.3.6.1.2.1.1.1.0',
    'sysObjectID': '1.3.6.1.2.1.1.2.0',
    'sysUpTime': '1.3.6.1.2.1.1.3.0',
    'sysContact': '1.3.6.1.2.1.1.4.0',
    'sysName': '1.3.6.1.2.1.1.5.0',
    'sysLocation': '1.3.6.1.2.1.1.6.0',
    # Interface MIB
    'ifNumber': '1.3.6.1.2.1.2.1.0',
    'ifIndex': '1.3.6.1.2.1.2.2.1.1',
    'ifDescr': '1.3.6.1.2.1.2.2.1.2',
    'ifType': '1.3.6.1.2.1.2.2.1.3',
    'ifSpeed': '1.3.6.1.2.1.2.2.1.5',
    'ifPhysAddress': '1.3.6.1.2.1.2.2.1.6',
    'ifAdminStatus': '1.3.6.1.2.1.2.2.1.7',
    'ifOperStatus': '1.3.6.1.2.1.2.2.1.8',
    'ifInOctets': '1.3.6.1.2.1.2.2.1.10',
    'ifOutOctets': '1.3.6.1.2.1.2.2.1.16',
    'ifInErrors': '1.3.6.1.2.1.2.2.1.14',
    'ifOutErrors': '1.3.6.1.2.1.2.2.1.20',
    'ifInDiscards': '1.3.6.1.2.1.2.2.1.13',
    'ifOutDiscards': '1.3.6.1.2.1.2.2.1.19',
    # CPU / Memory (华为私有 MIB 示例)
    'hwCpuUsage': '1.3.6.1.4.1.2011.5.25.31.1.1.1.1.5',
    'hwMemoryUsage': '1.3.6.1.4.1.2011.5.25.31.1.1.1.1.7',
    # LLDP —— 远端邻居表 lldpRemTable，索引为 <timeMark>.<localPortNum>.<remIndex>
    'lldpRemChassisId': '1.0.8802.1.1.2.1.4.1.1.5',
    'lldpRemPortId': '1.0.8802.1.1.2.1.4.1.1.7',
    'lldpRemPortDesc': '1.0.8802.1.1.2.1.4.1.1.8',
    'lldpRemSysName': '1.0.8802.1.1.2.1.4.1.1.9',
    'lldpRemSysDesc': '1.0.8802.1.1.2.1.4.1.1.10',
    # LLDP —— 本端端口表 lldpLocPortTable，索引为 <localPortNum>
    'lldpLocPortId': '1.0.8802.1.1.2.1.3.7.1.3',
    'lldpLocPortDesc': '1.0.8802.1.1.2.1.3.7.1.4',
    # ARP
    'ipNetToMediaPhysAddress': '1.3.6.1.2.1.4.22.1.2',
    'ipNetToMediaNetAddress': '1.3.6.1.2.1.4.22.1.3',
}

# 接口状态映射
IF_STATUS_MAP = {1: 'up', 2: 'down', 3: 'testing', 4: 'unknown', 5: 'dormant',
                 6: 'notPresent', 7: 'lowerLayerDown'}


class SNMPCollector(BaseCollector):
    """SNMP 采集器"""

    def __init__(self, ip_address, credential=None, timeout=5, retries=2):
        super().__init__(ip_address, credential, timeout, retries)
        self._engine = SnmpEngine()
        self._auth_data = None
        self._transport = None

    def connect(self):
        """建立 SNMP 连接"""
        cred = self.credential
        if cred:
            if cred.snmp_version == 'v3':
                auth_proto = usmHMACSHAAuthProtocol if 'sha' in (cred.snmp_security_level or '').lower() else usmHMACMD5AuthProtocol
                priv_proto = usmAesCfb128Protocol if 'aes' in (cred.snmp_security_level or '').lower() else usmDESPrivProtocol
                self._auth_data = UsmUserData(
                    cred.username, cred.password,
                    authProtocol=auth_proto,
                    privProtocol=priv_proto,
                )
            else:
                self._auth_data = CommunityData(cred.community or 'public')
        else:
            self._auth_data = CommunityData('public')

        self._transport = UdpTransportTarget(
            (self.ip_address, 161),
            timeout=self.timeout,
            retries=self.retries,
        )
        self._connected = True
        logger.info(f'SNMP 连接建立: {self.ip_address}')

    def disconnect(self):
        """断开 SNMP 连接"""
        self._connected = False
        logger.debug(f'SNMP 连接断开: {self.ip_address}')

    def _snmp_get(self, *oids):
        """SNMP GET"""
        objects = [ObjectType(ObjectIdentity(oid)) for oid in oids]
        error_indication, error_status, error_index, var_binds = next(
            getCmd(self._engine, self._auth_data, self._transport, ContextData(), *objects)
        )
        if error_indication:
            logger.error(f'SNMP GET error: {self.ip_address} - {error_indication}')
            return None
        if error_status:
            logger.error(f'SNMP GET error: {self.ip_address} - {error_status.prettyPrint()}')
            return None
        return {str(name): val for name, val in var_binds}

    def _snmp_walk(self, oid):
        """SNMP WALK (GETNEXT)"""
        results = []
        for (error_indication, error_status, error_index, var_binds) in nextCmd(
            self._engine, self._auth_data, self._transport, ContextData(),
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False,
        ):
            if error_indication or error_status:
                logger.error(f'SNMP WALK error: {self.ip_address} - {error_indication or error_status}')
                break
            for name, val in var_binds:
                results.append((str(name), val))
        return results

    def get_system_info(self):
        """获取设备基本信息"""
        result = self._snmp_get(
            OIDS['sysDescr'], OIDS['sysObjectID'],
            OIDS['sysName'], OIDS['sysUpTime'],
            OIDS['sysLocation'], OIDS['sysContact'],
        )
        if not result:
            return None
        return {
            'sysdescr': str(result.get(OIDS['sysDescr'], '')),
            'sysobjectid': str(result.get(OIDS['sysObjectID'], '')),
            'sysname': str(result.get(OIDS['sysName'], '')),
            'sysuptime': self._safe_int(result.get(OIDS['sysUpTime'], 0)),
            'syslocation': str(result.get(OIDS['sysLocation'], '')),
            'syscontact': str(result.get(OIDS['sysContact'], '')),
        }

    def get_interfaces(self):
        """获取接口列表"""
        if_indices = self._snmp_walk(OIDS['ifIndex'])
        if not if_indices:
            return []

        interfaces = []
        if_descrs = dict(self._snmp_walk(OIDS['ifDescr']))
        if_speeds = dict(self._snmp_walk(OIDS['ifSpeed']))
        if_admin = dict(self._snmp_walk(OIDS['ifAdminStatus']))
        if_oper = dict(self._snmp_walk(OIDS['ifOperStatus']))
        if_macs = dict(self._snmp_walk(OIDS['ifPhysAddress']))
        if_in_oct = dict(self._snmp_walk(OIDS['ifInOctets']))
        if_out_oct = dict(self._snmp_walk(OIDS['ifOutOctets']))
        if_in_err = dict(self._snmp_walk(OIDS['ifInErrors']))
        if_out_err = dict(self._snmp_walk(OIDS['ifOutErrors']))

        for oid, index in if_indices:
            idx = str(index)
            interfaces.append({
                'index': self._safe_int(index),
                'name': str(if_descrs.get(f'{OIDS["ifDescr"]}.{idx}', '')),
                'speed': self._safe_int(if_speeds.get(f'{OIDS["ifSpeed"]}.{idx}', 0)),
                'admin_status': self._safe_int(if_admin.get(f'{OIDS["ifAdminStatus"]}.{idx}', 1)),
                'oper_status': IF_STATUS_MAP.get(
                    self._safe_int(if_oper.get(f'{OIDS["ifOperStatus"]}.{idx}', 4)), 'unknown'
                ),
                'mac_address': self._format_mac(if_macs.get(f'{OIDS["ifPhysAddress"]}.{idx}', b'')),
                'in_octets': self._safe_int(if_in_oct.get(f'{OIDS["ifInOctets"]}.{idx}', 0)),
                'out_octets': self._safe_int(if_out_oct.get(f'{OIDS["ifOutOctets"]}.{idx}', 0)),
                'in_errors': self._safe_int(if_in_err.get(f'{OIDS["ifInErrors"]}.{idx}', 0)),
                'out_errors': self._safe_int(if_out_err.get(f'{OIDS["ifOutErrors"]}.{idx}', 0)),
            })
        return interfaces

    def get_cpu_usage(self):
        """获取 CPU 使用率（华为设备 OID）"""
        results = self._snmp_walk(OIDS['hwCpuUsage'])
        if results:
            return [self._safe_float(val) for _, val in results]
        return []

    def get_memory_usage(self):
        """获取内存使用率（华为设备 OID）"""
        results = self._snmp_walk(OIDS['hwMemoryUsage'])
        if results:
            return [self._safe_float(val) for _, val in results]
        return []

    def get_lldp_neighbors(self):
        """
        获取 LLDP 邻居

        返回: [{
            'local_port_num': int,   # lldpRemLocalPortNum
            'local_port':     str,   # 本端端口名（优先 PortDesc，回退 PortId / ifDescr）
            'remote_chassis': str,   # 远端机箱标识（多为 MAC）
            'remote_port':    str,   # 远端端口
            'remote_system':  str,   # 远端设备名
            'remote_descr':   str,
        }]
        """
        chassis_ids = dict(self._snmp_walk(OIDS['lldpRemChassisId']))
        if not chassis_ids:
            return []

        port_ids = dict(self._snmp_walk(OIDS['lldpRemPortId']))
        port_descs = dict(self._snmp_walk(OIDS['lldpRemPortDesc']))
        sys_names = dict(self._snmp_walk(OIDS['lldpRemSysName']))
        sys_descs = dict(self._snmp_walk(OIDS['lldpRemSysDesc']))

        # 本端端口号 → 端口名
        loc_port_map = {}
        for oid, val in self._snmp_walk(OIDS['lldpLocPortDesc']):
            loc_port_map[oid.rsplit('.', 1)[-1]] = self._decode(val)
        for oid, val in self._snmp_walk(OIDS['lldpLocPortId']):
            key = oid.rsplit('.', 1)[-1]
            if not loc_port_map.get(key):
                loc_port_map[key] = self._decode(val)

        # 部分设备 lldpRemLocalPortNum 即 ifIndex，作为兜底映射
        if_descr_map = {
            oid.rsplit('.', 1)[-1]: self._decode(val)
            for oid, val in self._snmp_walk(OIDS['ifDescr'])
        }

        neighbors = []
        for oid, chassis_id in chassis_ids.items():
            parts = oid.split('.')
            if len(parts) < 3:
                continue
            index = '.'.join(parts[-3:])       # timeMark.localPortNum.remIndex
            local_port_num = parts[-2]

            local_port = (
                loc_port_map.get(local_port_num)
                or if_descr_map.get(local_port_num)
                or ''
            )
            remote_port = (
                self._decode(port_descs.get(f'{OIDS["lldpRemPortDesc"]}.{index}'))
                or self._decode(port_ids.get(f'{OIDS["lldpRemPortId"]}.{index}'))
            )

            neighbors.append({
                'local_port_num': self._safe_int(local_port_num),
                'local_port': local_port,
                'remote_chassis': self._decode(chassis_id),
                'remote_port': remote_port,
                'remote_system': self._decode(sys_names.get(f'{OIDS["lldpRemSysName"]}.{index}')),
                'remote_descr': self._decode(sys_descs.get(f'{OIDS["lldpRemSysDesc"]}.{index}')),
            })
        return neighbors

    @staticmethod
    def _decode(value):
        """SNMP 值转字符串；MAC 型 OctetString 自动格式化"""
        if value is None:
            return ''
        try:
            raw = value.asOctets() if hasattr(value, 'asOctets') else value
        except Exception:
            raw = value
        if isinstance(raw, bytes):
            if len(raw) == 6 and not all(32 <= b < 127 for b in raw):
                return ':'.join(f'{b:02x}' for b in raw)
            try:
                return raw.decode('utf-8', errors='ignore').strip('\x00').strip()
            except Exception:
                return raw.hex()
        return str(raw).strip()

    def get_arp_table(self):
        """获取 ARP 表"""
        macs = dict(self._snmp_walk(OIDS['ipNetToMediaPhysAddress']))
        ips = dict(self._snmp_walk(OIDS['ipNetToMediaNetAddress']))

        arp_entries = []
        for oid, mac in macs.items():
            ip = ips.get(oid.replace(
                OIDS['ipNetToMediaPhysAddress'],
                OIDS['ipNetToMediaNetAddress']
            ))
            if ip:
                arp_entries.append({
                    'ip_address': str(ip),
                    'mac_address': self._format_mac(mac),
                })
        return arp_entries

    def get_custom_oid(self, oid):
        """获取自定义 OID"""
        result = self._snmp_get(oid)
        if result:
            return list(result.values())[0]
        return None

    @staticmethod
    def _format_mac(mac_bytes):
        """格式化 MAC 地址"""
        if isinstance(mac_bytes, bytes) and len(mac_bytes) == 6:
            return ':'.join(f'{b:02x}' for b in mac_bytes)
        return str(mac_bytes)
