# -*- coding: utf-8 -*-
"""
网络自动发现引擎

职责（纯逻辑，不依赖 Celery，便于单测）：
    1. IP 范围展开：CIDR / 起止区间 / 单 IP
    2. 存活探测：ICMP ping
    3. 设备识别：SNMP sysDescr / sysObjectID → 厂商 + 设备类型
    4. 接口与 LLDP 邻居抓取
"""
import ipaddress
import logging
import re

logger = logging.getLogger('esight.discovery')

# ---------------------------------------------------------------- 厂商识别表
# key: sysObjectID 前缀（企业私有 OID），value: (厂商名称, 厂商编码)
ENTERPRISE_OID_MAP = [
    ('1.3.6.1.4.1.2011', ('华为', 'huawei')),
    ('1.3.6.1.4.1.2011.2.240', ('华为', 'huawei')),
    ('1.3.6.1.4.1.9', ('思科', 'cisco')),
    ('1.3.6.1.4.1.25506', ('新华三', 'h3c')),
    ('1.3.6.1.4.1.43', ('新华三', 'h3c')),
    ('1.3.6.1.4.1.2636', ('瞻博', 'juniper')),
    ('1.3.6.1.4.1.4881', ('锐捷', 'ruijie')),
    ('1.3.6.1.4.1.674', ('戴尔', 'dell')),
    ('1.3.6.1.4.1.232', ('慧与', 'hpe')),
    ('1.3.6.1.4.1.343', ('英特尔', 'intel')),
    ('1.3.6.1.4.1.311', ('微软', 'microsoft')),
    ('1.3.6.1.4.1.8072', ('Net-SNMP', 'net-snmp')),
    ('1.3.6.1.4.1.6876', ('VMware', 'vmware')),
    ('1.3.6.1.4.1.12356', ('飞塔', 'fortinet')),
    ('1.3.6.1.4.1.3375', ('F5', 'f5')),
]

# sysDescr 关键字 → 厂商，兜底用
VENDOR_KEYWORDS = [
    (r'huawei|versatile routing platform|vrp', ('华为', 'huawei')),
    (r'cisco|ios software|nx-os', ('思科', 'cisco')),
    (r'h3c|comware', ('新华三', 'h3c')),
    (r'juniper|junos', ('瞻博', 'juniper')),
    (r'ruijie|rgos', ('锐捷', 'ruijie')),
    (r'fortigate|fortios', ('飞塔', 'fortinet')),
    (r'\bvmware\b|esxi', ('VMware', 'vmware')),
    (r'windows', ('微软', 'microsoft')),
    (r'linux|ubuntu|centos|debian|red hat', ('Linux', 'linux')),
]

# sysDescr / sysObjectID 关键字 → 设备类型 (code, 名称, 图标)
# 顺序敏感：先匹配到的优先
TYPE_KEYWORDS = [
    (r'firewall|fortigate|fortios|usg\d|asa\b|srg\b|防火墙', ('firewall', '防火墙', 'md-lock')),
    (r'\bwlc\b|access controller|无线控制器', ('wlc', '无线控制器', 'md-wifi')),
    (r'\bap\b|access point|wireless', ('ap', '无线 AP', 'md-wifi')),
    (r'load ?balanc|\bf5\b|big-?ip', ('loadbalancer', '负载均衡', 'md-swap')),
    (r'storage|oceanstor|netapp|存储', ('storage', '存储设备', 'md-albums')),
    (r'router|\bvrp\b.*router|ar\d{3,}|ne\d{2,}|路由器', ('router', '路由器', 'md-globe')),
    (r'switch|s\d{4}|ce\d{4}|catalyst|nexus|交换机', ('switch', '交换机', 'md-git-network')),
    (r'linux|windows|ubuntu|centos|debian|red hat|esxi|server', ('server', '服务器', 'md-desktop')),
    (r'printer|打印机', ('printer', '打印机', 'md-print')),
]

DEFAULT_TYPE = ('unknown', '未知设备', 'md-help')

# ifNumber 少于该值且无网络关键字时，倾向判定为服务器
_SERVER_IF_THRESHOLD = 6


# ---------------------------------------------------------------- IP 范围展开
def expand_ip_ranges(ip_ranges, max_hosts=65536):
    """
    展开 IP 范围为 IP 列表（去重、保序）。

    支持三种写法：
        - CIDR：      192.168.1.0/24   （自动剔除网络地址与广播地址）
        - 起止区间：  10.0.0.1-10.0.0.254 或 10.0.0.1-254
        - 单个 IP：   192.168.1.1

    :param ip_ranges: str 或 list[str]
    :param max_hosts: 保护上限，超出后截断
    :return: list[str]
    """
    if isinstance(ip_ranges, str):
        ip_ranges = [ip_ranges]

    seen = set()
    result = []

    for raw in ip_ranges or []:
        item = (raw or '').strip()
        if not item:
            continue
        try:
            hosts = _expand_single(item)
        except ValueError as exc:
            logger.warning('无法解析 IP 范围 %r: %s', item, exc)
            continue

        for ip in hosts:
            if ip in seen:
                continue
            seen.add(ip)
            result.append(ip)
            if len(result) >= max_hosts:
                logger.warning('IP 数量已达上限 %s，后续范围被截断', max_hosts)
                return result
    return result


def _expand_single(item):
    """展开单条 IP 范围表达式"""
    # CIDR
    if '/' in item:
        net = ipaddress.ip_network(item, strict=False)
        if net.prefixlen >= 31:  # /31 /32 直接全取
            return [str(ip) for ip in net]
        return [str(ip) for ip in net.hosts()]

    # 起止区间
    if '-' in item:
        start_str, end_str = [p.strip() for p in item.split('-', 1)]
        start = ipaddress.ip_address(start_str)
        # 支持 10.0.0.1-254 简写
        if '.' not in end_str:
            prefix = start_str.rsplit('.', 1)[0]
            end_str = f'{prefix}.{end_str}'
        end = ipaddress.ip_address(end_str)
        if int(end) < int(start):
            raise ValueError('结束地址小于起始地址')
        return [str(ipaddress.ip_address(i)) for i in range(int(start), int(end) + 1)]

    # 单 IP
    return [str(ipaddress.ip_address(item))]


# ---------------------------------------------------------------- 识别
def identify_vendor(sysobjectid='', sysdescr=''):
    """根据 sysObjectID / sysDescr 识别厂商，返回 (名称, 编码)"""
    oid = (sysobjectid or '').strip()
    if oid:
        # 最长前缀优先
        matches = [v for prefix, v in ENTERPRISE_OID_MAP if oid.startswith(prefix + '.') or oid == prefix]
        if matches:
            longest = max(
                (p for p, _ in ENTERPRISE_OID_MAP if oid.startswith(p + '.') or oid == p),
                key=len,
            )
            return dict(ENTERPRISE_OID_MAP)[longest]

    descr = (sysdescr or '').lower()
    for pattern, vendor in VENDOR_KEYWORDS:
        if re.search(pattern, descr):
            return vendor
    return ('未知厂商', 'unknown')


def identify_device_type(sysdescr='', sysobjectid='', if_count=0):
    """
    识别设备类型，返回 (code, 名称, 图标)

    先按 sysDescr 关键字匹配；匹配不到时用接口数量做启发式判断。
    """
    text = f'{sysdescr or ""} {sysobjectid or ""}'.lower()
    for pattern, dev_type in TYPE_KEYWORDS:
        if re.search(pattern, text):
            return dev_type

    # 启发式：接口很多 → 网络设备（按交换机处理）；接口很少 → 服务器
    if if_count >= _SERVER_IF_THRESHOLD:
        return ('switch', '交换机', 'md-git-network')
    if 0 < if_count < _SERVER_IF_THRESHOLD:
        return ('server', '服务器', 'md-desktop')
    return DEFAULT_TYPE


def parse_os_version(sysdescr=''):
    """从 sysDescr 中粗略提取版本号"""
    if not sysdescr:
        return ''
    patterns = [
        r'Version\s+([\w.\-()]+)',
        r'VRP.*?Version\s+([\w.\-()]+)',
        r'\bv?(\d+\.\d+[\w.\-]*)',
    ]
    for pattern in patterns:
        match = re.search(pattern, sysdescr, re.IGNORECASE)
        if match:
            return match.group(1).rstrip(',.')[:64]
    return ''


# ---------------------------------------------------------------- 单机扫描
def probe_host(ip, credentials=None, protocols=None, timeout=3):
    """
    探测单台主机。

    :param ip:          目标 IP
    :param credentials: cmdb.Credential 列表，按顺序尝试（仅使用 snmp 类）
    :param protocols:   启用的协议，默认 ['icmp', 'snmp']
    :param timeout:     单次探测超时（秒）
    :return: dict — 始终返回，通过 alive / snmp_ok 判断结果
    """
    from collectors.ping_check import ping_check

    protocols = protocols or ['icmp', 'snmp']
    record = {
        'ip': ip,
        'alive': False,
        'snmp_ok': False,
        'hostname': '',
        'sysdescr': '',
        'sysobjectid': '',
        'location': '',
        'vendor': '',
        'vendor_code': '',
        'device_type': DEFAULT_TYPE[0],
        'device_type_name': DEFAULT_TYPE[1],
        'icon': DEFAULT_TYPE[2],
        'os_version': '',
        'mac_address': '',
        'credential_id': None,
        'interfaces': [],
        'lldp_neighbors': [],
        'error': '',
    }

    # 1) ICMP 存活探测
    if 'icmp' in protocols:
        record['alive'] = ping_check(ip, timeout=timeout)
        if not record['alive'] and 'snmp' not in protocols:
            return record
    else:
        record['alive'] = True  # 跳过 ping，直接试 SNMP

    # 2) SNMP 采集
    if 'snmp' in protocols:
        snmp_creds = [
            c for c in (credentials or [])
            if getattr(c, 'protocol', '').startswith('snmp')
        ] or [None]  # None → 采集器内部退化为 public

        for cred in snmp_creds:
            info = _try_snmp(ip, cred, protocols, timeout, record)
            if info:
                record['credential_id'] = getattr(cred, 'id', None)
                break

    # SNMP 成功即视为存活（有些设备禁 ping）
    if record['snmp_ok']:
        record['alive'] = True
    return record


def _try_snmp(ip, cred, protocols, timeout, record):
    """用单个凭据尝试 SNMP 采集，成功返回 True"""
    from collectors.snmp_collector import SNMPCollector

    try:
        with SNMPCollector(ip, cred, timeout=timeout, retries=1) as collector:
            sys_info = collector.get_system_info()
            if not sys_info:
                return False

            record['snmp_ok'] = True
            record['hostname'] = sys_info.get('sysname', '') or ''
            record['sysdescr'] = sys_info.get('sysdescr', '') or ''
            record['sysobjectid'] = sys_info.get('sysobjectid', '') or ''
            record['location'] = sys_info.get('syslocation', '') or ''
            record['os_version'] = parse_os_version(record['sysdescr'])

            # 接口
            try:
                interfaces = collector.get_interfaces() or []
            except Exception as exc:  # 部分设备不支持 IF-MIB
                logger.debug('接口采集失败 %s: %s', ip, exc)
                interfaces = []
            record['interfaces'] = interfaces
            for iface in interfaces:
                mac = (iface.get('mac_address') or '').strip()
                if mac and mac not in ('00:00:00:00:00:00',):
                    record['mac_address'] = mac
                    break

            # LLDP 邻居
            if 'lldp' in protocols:
                try:
                    record['lldp_neighbors'] = collector.get_lldp_neighbors() or []
                except Exception as exc:
                    logger.debug('LLDP 采集失败 %s: %s', ip, exc)

            vendor, vendor_code = identify_vendor(record['sysobjectid'], record['sysdescr'])
            dev_code, dev_name, icon = identify_device_type(
                record['sysdescr'], record['sysobjectid'], len(interfaces),
            )
            record.update({
                'vendor': vendor,
                'vendor_code': vendor_code,
                'device_type': dev_code,
                'device_type_name': dev_name,
                'icon': icon,
            })
            return True
    except Exception as exc:
        record['error'] = str(exc)[:200]
        logger.debug('SNMP 探测失败 %s (cred=%s): %s', ip, getattr(cred, 'name', 'public'), exc)
    return False
