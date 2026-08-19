# -*- coding: utf-8 -*-
"""
eSight 本地网络执行器（Local Network Executor）
================================================
2026-08-13 新增：eSight 内建控制器执行能力，替代对平台 opsany-paas-proxy 的依赖。

背景
----
opsany-paas-proxy 是 OpsAny 平台级共享组件（gunicorn :8010 + celery），eSight 通过
ControllerAdmin 配置的 proxy_url 调它的 /api/proxy/v0_1/ 接口执行设备操作（SSH/Telnet=netmiko、
SNMP=snmpwalk 命令行）。问题：
  1. 换正式环境要重新配置/依赖平台组件；
  2. 平台自身 bug（sys_log 分支调错函数、command_dict 缺带连接方式键）patch 了也不随新环境走；
  3. 多一跳 HTTP + 跨容器。

本模块把 agent 实际用到的执行逻辑移植进 eSight：
  - SSH/Telnet：netmiko（venv 已装 4.3.0），command_dict 已含 eSight 修复（huawei_telnet 等键 + dis logbuffer）
  - SNMP：**snmpwalk 命令行**（/usr/bin/snmpwalk，net-snmp）——与 agent 完全一致（agent 也是
    subprocess 调 snmpwalk）。不用 pysnmp：py3.12 移除 asyncore 导致旧版 pysnmp 崩，且
    venv 中 pysnmp 4.4.12 与 pysnmp-lextudio 6.3.0 文件混杂。要求系统有 net-snmp 工具
    （OpsAny 平台镜像默认自带，与 agent 同款）。

ControllerAdmin.exec_mode：
  - 'agent'：走 HTTP 调平台 opsany-paas-proxy（默认，兼容现状）
  - 'local'：进程内直接调本模块（推荐，单应用交付）

本地执行函数返回格式与 agent 接口完全一致（data 部分），供 _ProxyApi._request 直接透传。
"""
import datetime
import logging
import re

logger = logging.getLogger('app')

# ======================================================================
# SSH / Telnet 执行器（移植 proxy/api/network_ssh_api.py + 2026-08-13 patch）
# ======================================================================
# 2026-08-13 eSight 修复：NetworkSSHApi.__init__ 里 device_type = device_type + "_" + connection_type.lower()
# （如 huawei_telnet），原 command_dict 只有裸键（huawei），导致查不到 → fallback "dis log"，
# 华为 VRP 报 "Incomplete command"，正确命令是 "dis logbuffer"。补齐带连接方式的键。
command_dict = {
    "hp_comware": {"ping": "dis version", "cpu": "dis cpu", "memory": "dis memory", "log": "dis log"},
    "huawei": {"ping": "dis version", "cpu": "dis cpu", "memory": "dis memory", "log": "dis log"},
    "cisco_ios": {"ping": "show version", "cpu": "show cpu", "memory": "show memory", "log": "show log"},
}
for _conn in ("ssh", "telnet"):
    command_dict["huawei_" + _conn] = {
        "ping": "dis version", "cpu": "dis cpu", "memory": "dis memory", "log": "dis logbuffer",
    }
    command_dict["hp_comware_" + _conn] = {
        "ping": "dis version", "cpu": "dis cpu", "memory": "dis memory", "log": "dis logbuffer",
    }
    command_dict["cisco_ios_" + _conn] = {
        "ping": "show version", "cpu": "show cpu", "memory": "show memory", "log": "show logging",
    }


class NetworkSSHApi:
    """SSH/Telnet 连接执行器（netmiko）。与 opsany-paas-proxy proxy/api/network_ssh_api.py 同构。"""

    def __init__(self, ip, port, login_username, login_password, device_type="hp_comware",
                 connection_type="SSH", ssh_timeout=15):
        self.device_type = str(device_type or "") + "_" + str(connection_type).lower()
        self.connection_type = connection_type
        self.ip = ip
        self.timeout = ssh_timeout or 15
        self.port = port
        self.username = login_username
        self.password = login_password
        self.conn = None
        self.message = ""
        self.net_connect = self._net_connect()

    def _net_connect(self):
        try:
            from netmiko import ConnectHandler
        except Exception as e:
            self.message = "netmiko 未安装: {}".format(e)
            return None
        dic = dict(
            device_type=self.device_type,
            ip=self.ip,
            port=int(self.port or (22 if self.connection_type == "SSH" else 23)),
            timeout=self.timeout,
            conn_timeout=self.timeout,
        )
        if self.connection_type == "SSH":
            dic.update(username=self.username, password=self.password, fast_cli=True)
        else:
            if self.username:
                dic["username"] = self.username
            if self.password:
                dic["password"] = self.password
        try:
            net_connect = ConnectHandler(**dic)
            net_connect.timeout = self.timeout
            try:
                net_connect.session_timeout = self.timeout
            except Exception:
                pass
            net_connect.find_prompt()
            self.conn = net_connect
            self.message = "Success"
            return net_connect
        except Exception as e:
            self.message = str(e)
            self.conn = None
            return None

    def test_ping(self):
        if not self.conn:
            return False, self.message or "连接失败"
        try:
            self.conn.is_alive()
            return True, "Success"
        except Exception as e:
            return False, str(e)

    def get_cup_memory(self):
        if not self.conn:
            return False, self.message or "连接失败"
        dic = {}
        try:
            cpu_command = command_dict.get(self.device_type, {}).get("cpu", "dis cpu")
            memory_command = command_dict.get(self.device_type, {}).get("memory", "dis memory")
            cpu_output = self.conn.send_command(cpu_command)
            if "Unrecognized" in cpu_output:
                return False, dic
            memory_output = self.conn.send_command(memory_command)
            cpu_re, memory_re = re.compile(r'(\d*)%', re.S), re.compile(r': (\d*)', re.S)
            cpu_list = cpu_re.findall(cpu_output)
            memory_list = memory_re.findall(memory_output)
            if len(cpu_list) == 3:
                dic["cpu_5s"] = cpu_list[0]
                dic["cpu_1m"] = cpu_list[1]
                dic["cpu_5m"] = cpu_list[2]
            if len(memory_list) == 3:
                dic["total_memory"] = memory_list[0]
                dic["total_used"] = memory_list[1]
                dic["used_rate"] = memory_list[2]
            if not dic:
                return False, dic
            return True, dic
        except Exception as e:
            return False, str(e)

    def get_cpu_mem(self):
        """精确采集 CPU/内存使用率（适配华为/华三 VRP 真实输出）。返回 {cpu, mem}。"""
        if not self.conn:
            return False, self.message or "连接失败"
        try:
            cpu_command = command_dict.get(self.device_type, {}).get("cpu", "dis cpu")
            memory_command = command_dict.get(self.device_type, {}).get("memory", "dis memory")
            cpu_output = self.conn.send_command(cpu_command)
            memory_output = self.conn.send_command(memory_command)
            cpu, mem = '', ''
            # CPU: "CPU Usage            : 20% Max: 73%" 或 "five seconds: 20%"
            m = re.search(r'CPU Usage\s*:\s*(\d+)%', cpu_output) or re.search(r'five seconds:\s*(\d+)%', cpu_output)
            if m:
                cpu = m.group(1)
            # 内存: "Memory Using Percentage Is: 51%"（华为）或 "Memory using percentage is: 51%"
            m = re.search(r'[Mm]emory [Uu]sing [Pp]ercentage [Ii]s:\s*(\d+)%', memory_output)
            if not m:
                m = re.search(r'(\d+)%\s*$', memory_output, re.M)  # 兜底：行尾的百分比
            if m:
                mem = m.group(1)
            return True, {'cpu': cpu, 'mem': mem}
        except Exception as e:
            return False, str(e)

    def get_sys_log_info(self):
        if not self.conn:
            return False, self.message or "连接失败"
        dic = {}
        try:
            log_command = command_dict.get(self.device_type, {}).get("log", "dis log")
            log_output = self.conn.send_command(log_command)
            if "Unrecognized" in log_output:
                return False, dic
            if not log_output:
                return False, log_output
            dic["log"] = log_output.split("%") if log_output else log_output
            return True, dic
        except Exception as e:
            return False, str(e)

    def get_boot_config(self, boot_config_script):
        if not self.conn:
            return False, self.message or "连接失败"
        command_lines = (boot_config_script or "").splitlines()
        start_output = '{} 共执行 {} 条备份命令！\n'.format(
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M"), len(command_lines))
        start_output += (boot_config_script or "") + "\n\n"
        lens = 1
        try:
            for i in command_lines:
                i = i.strip()
                start_output += "#--------------------------------\n"
                start_output += "# 命令 {}：{}\n".format(lens, i)
                start_output += "#--------------------------------\n"
                start_output += self.conn.send_command_timing(i)
                start_output += "\n\n"
                lens += 1
        except Exception as e:
            return False, str(e)
        dic = {"boot_config_script": boot_config_script, "boot_config_content": start_output}
        return True, dic

    def get_run_config(self, running_config_script):
        if not self.conn:
            return False, self.message or "连接失败"
        command_lines = (running_config_script or "").splitlines()
        run_output = '{} 共执行 {} 条备份命令！\n'.format(
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M"), len(command_lines))
        run_output += (running_config_script or "") + "\n\n"
        lens = 1
        try:
            for i in command_lines:
                i = i.strip()
                run_output += "#--------------------------------\n"
                run_output += "# 命令 {}：{}\n".format(lens, i)
                run_output += "#--------------------------------\n"
                run_output += self.conn.send_command_timing(i)
                run_output += "\n\n"
                lens += 1
        except Exception as e:
            return False, str(e)
        dic = {"running_config_script": running_config_script, "running_config_content": run_output}
        return True, dic

    def close(self):
        try:
            if self.net_connect:
                self.net_connect.disconnect()
        except Exception:
            pass

    def __del__(self):
        try:
            if getattr(self, "net_connect", None):
                self.net_connect.disconnect()
        except Exception:
            pass


# ======================================================================
# SNMP 执行器（移植 proxy/api/network_snmp_api.py，snmpwalk 换 pysnmp）
# ======================================================================
DEVICE_OID_LIST = {
    "public": {
        "sysName": "sysName", "sysDescr": "sysDescr", "sysLocation": "sysLocation",
        "sysContact": "sysContact", "sysUpTime": "sysUpTime", "sysObjectID": "sysObjectID",
        "memTotalReal": "memTotalReal", "memTotalFree": "memTotalFree",
        "ifIndex": "ifIndex", "ifName": "ifName", "ifDescr": "ifDescr", "ifAlias": "ifAlias",
        "ifSpeed": "ifSpeed", "ifHighSpeed": "ifHighSpeed",
        "ifAdminStatus": "ifAdminStatus", "ifOperStatus": "ifOperStatus",
        "ifHCInOctets": "ifHCInOctets", "ifHCOutOctets": "ifHCOutOctets",
        "ifType": "ifType", "ifPhysAddress": "ifPhysAddress",
        "ifInOctets": "ifInOctets", "ifOutOctets": "ifOutOctets",
        "ipNetToMediaIfIndex": "ipNetToMediaIfIndex",
        "ipNetToMediaPhysAddress": "ipNetToMediaPhysAddress",
        "ipNetToMediaNetAddress": "ipNetToMediaNetAddress",
        "ipAdEntAddr": "ipAdEntAddr", "ipAdEntNetMask": "ipAdEntNetMask",
        "ipNetToMediaType": "ipNetToMediaType",
        "cpu_ratio": "1.3.6.1.4.1.25506.8.35.18.1.3",
        "memory_ratio": "1.3.6.1.4.1.25506.8.35.18.1.16",
        "entPhysicalName": "1.3.6.1.2.1.47.1.1.1.1.7",
        "hh3cEntityExtCpuUsage": ".1.3.6.1.4.1.25506.2.6.1.1.1.1.6",
        "hh3cEntityExtCpuUsage_One": ".1.3.6.1.4.1.25506.2.6.1.1.1.1.6.{}",
        "hh3cEntityExtCpuUsage_One_new": ".1.3.6.1.4.1.2011.10.2.6.1.1.1.1.8.{}",
        "hh3cEntityExtMemUsage_One": ".1.3.6.1.4.1.25506.2.6.1.1.1.1.8.{}",
        "hh3cEntityExtMemUsage_One_new": ".1.3.6.1.4.1.2011.10.2.6.1.1.1.1.8.{}",
    },
    "default": {
        "sys_version": "HH3C-LSW-DEV-ADM-MIB::hh3cLswSysVersion",
        "cpu_ratio": "HH3C-LSW-DEV-ADM-MIB::hh3cLswSysCpuRatio",
        "memory_ratio": "HH3C-LSW-DEV-ADM-MIB::hh3cLswSysMemoryRatio",
        "hh3cLswSlotCpuRatio": "HH3C-LSW-DEV-ADM-MIB::hh3cLswSlotCpuRatio",
        "hh3cLswSlotMemoryRatio": "HH3C-LSW-DEV-ADM-MIB::hh3cLswSlotMemoryRatio",
    },
    "h3c": {
        "sys_version": "1.3.6.1.4.1.25506.8.35.18.1.4",
        "cpu_ratio": "1.3.6.1.4.1.25506.8.35.18.1.3",
        "memory_ratio": "1.3.6.1.4.1.25506.8.35.18.1.16",
    },
    "huawei": {
        "sys_version": "1.3.6.1.4.1.25506.8.35.18.1.4",
        "hwCpuDevDuty": "1.3.6.1.4.1.2011.6.3.4.1.2",
        "hwAvgDuty1min": "1.3.6.1.4.1.2011.6.3.4.1.3",
        "hwAvgDuty5min": "1.3.6.1.4.1.2011.6.3.4.1.4",
        "hwEntityCpuUsage": "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.5.{}",
        "hwEntityMemUsage": "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.7.{}",
    },
}

# 公共 MIB 符号名 → 数字 OID（pysnmp 无 MIB 文件时的兜底，保证任意环境可解析）
_COMMON_OID = {
    "sysName": ".1.3.6.1.2.1.1.5", "sysDescr": ".1.3.6.1.2.1.1.1",
    "sysLocation": ".1.3.6.1.2.1.1.6", "sysContact": ".1.3.6.1.2.1.1.4",
    "sysUpTime": ".1.3.6.1.2.1.1.3", "sysObjectID": ".1.3.6.1.2.1.1.2",
    "memTotalReal": ".1.3.6.1.2.1.25.2.3.1.5", "memTotalFree": ".1.3.6.1.2.1.25.2.3.1.6",
    "ifIndex": ".1.3.6.1.2.1.2.2.1.1", "ifName": ".1.3.6.1.2.1.31.1.1.1.1",
    "ifDescr": ".1.3.6.1.2.1.2.2.1.2", "ifAlias": ".1.3.6.1.2.1.31.1.1.1.18",
    "ifType": ".1.3.6.1.2.1.2.2.1.3", "ifPhysAddress": ".1.3.6.1.2.1.2.2.1.6",
    "ifAdminStatus": ".1.3.6.1.2.1.2.2.1.7", "ifOperStatus": ".1.3.6.1.2.1.2.2.1.8",
    "ifSpeed": ".1.3.6.1.2.1.2.2.1.5", "ifHighSpeed": ".1.3.6.1.2.1.31.1.1.1.15",
    "ifInOctets": ".1.3.6.1.2.1.2.2.1.10", "ifOutOctets": ".1.3.6.1.2.1.2.2.1.16",
    "ifHCInOctets": ".1.3.6.1.2.1.31.1.1.1.6", "ifHCOutOctets": ".1.3.6.1.2.1.31.1.1.1.10",
    "ipNetToMediaIfIndex": ".1.3.6.1.2.1.4.22.1.1",
    "ipNetToMediaPhysAddress": ".1.3.6.1.2.1.4.22.1.2",
    "ipNetToMediaNetAddress": ".1.3.6.1.2.1.4.22.1.3",
    "ipNetToMediaType": ".1.3.6.1.2.1.4.22.1.4",
    "ipAdEntAddr": ".1.3.6.1.2.1.4.20.1.1", "ipAdEntNetMask": ".1.3.6.1.2.1.4.20.1.3",
}


def _resolve_oid(oid):
    """OID 名称/符号 → 数字 OID 字符串；已是数字直接返回。"""
    oid = str(oid or "").strip()
    if not oid:
        return oid
    if oid in _COMMON_OID:
        return _COMMON_OID[oid]
    if oid[0].isdigit() or oid[0] == ".":
        return oid
    return oid  # 交给 pysnmp ObjectIdentity 尝试解析（如 MIB::节点）


def _snmpwalk_command(device_ip, udp_port, version, community, security_level, security_name,
                      verification_protocol, verify_password, privacy_protocol, private_key,
                      oid, timeout=15):
    """snmpwalk 命令行执行（与 opsany-paas-proxy agent 完全一致，agent 也是 subprocess 调 snmpwalk）。

    注意：容器/系统必须有 net-snmp 的 snmpwalk（/usr/bin/snmpwalk）。
    返回 (True, stdout文本) 或 (False, 脱敏后的错误信息)。"""
    import shutil
    if not shutil.which('snmpwalk'):
        return False, "系统缺少 snmpwalk 命令（net-snmp），无法执行 SNMP 采集"
    # 符号名 → 数字 OID（容器可能无 MIB 文件，snmpwalk 解析不了 sysName/ifIndex 等符号名）
    oid = _resolve_oid(oid)
    ver = str(version or "").lower()
    hostport = "{}:{}".format(device_ip, int(udp_port or 161))
    if ver in ("v1", "1"):
        command = "snmpwalk -v1 -c {} {} {}".format(community or "public", hostport, oid)
    elif ver in ("v2", "v2c", "2c", "2"):
        command = "snmpwalk -v2c -c {} {} {}".format(community or "public", hostport, oid)
    else:  # v3
        if security_level == "noAuthNoPriv":
            command = "snmpwalk -v 3 -u {security_name} -l noAuthNoPriv {hostport} {oid}".format(
                security_name=security_name or "", hostport=hostport, oid=oid)
        elif security_level == "authNoPriv":
            command = "snmpwalk -v 3 -u {security_name} -l authNoPriv -a {verification_protocol} -A {verify_password} {hostport} {oid}".format(
                security_name=security_name or "", verification_protocol=verification_protocol or "MD5",
                verify_password=verify_password or "", hostport=hostport, oid=oid)
        else:  # authPriv / 默认
            command = "snmpwalk -v 3 -u {security_name} -l authPriv -a {verification_protocol} -A {verify_password} -x {privacy_protocol} -X {private_key} {hostport} {oid}".format(
                security_name=security_name or "", verification_protocol=verification_protocol or "MD5",
                verify_password=verify_password or "", privacy_protocol=privacy_protocol or "DES",
                private_key=private_key or "", hostport=hostport, oid=oid)
    import subprocess
    try:
        r = subprocess.run(command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                           timeout=max(10, int(timeout or 15)))
        stdout = r.stdout.decode(errors="replace")
        stderr = r.stderr.decode(errors="replace")
        if stdout:
            return True, stdout
        if stderr:
            return False, _snmp_replace_password(stderr, community, security_name, verify_password, private_key)
        return False, "snmpwalk 无输出（OID 不存在或无权限）"
    except Exception as e:
        return False, _snmp_replace_password(str(e), community, security_name, verify_password, private_key)


def _snmp_replace_password(stderr, community, security_name, verify_password, private_key):
    """错误信息脱敏：不泄露 community/口令。"""
    for secret in (community, security_name, verify_password, private_key):
        if secret:
            stderr = stderr.replace(str(secret), "******")
    return stderr


class NetworkSnmpApi:
    """SNMP 采集执行器（pysnmp walk）。与 opsany-paas-proxy proxy/api/network_snmp_api.py 同构。"""

    def __init__(self, device_ip, version, community=None, security_name=None,
                 security_level="noAuthNoPriv", verification_protocol="MD5",
                 privacy_protocol="DES", verify_password=None, private_key=None,
                 udp_port=161, device_type=None, timeout=60):
        self.device_ip = device_ip
        self.snmp_version = version
        self.community = community
        self.udp_port = udp_port
        self.timeout = timeout
        self.security_name = security_name
        self.security_level = security_level
        self.verification_protocol = verification_protocol
        self.privacy_protocol = privacy_protocol
        self.verify_password = verify_password
        self.private_key = private_key
        self.device_type = self._clean_device_type(device_type) if device_type else self.get_device_type()

    def _clean_device_type(self, device_type):
        if device_type:
            if device_type in ["hp_comware", "hp_procurve"]:
                return "h3c"
            elif device_type in ["huawei", "huawei_smartax", "huawei_olt", "huawei_vrpv8"]:
                return "huawei"
            else:
                return "h3c"
        return "h3c"

    def get_device_type(self):
        status, message = self.get_sys_descr()
        device_type_list = ["h3c", "huawei", "cisco", "inspur"]
        device_type = "h3c"
        if status:
            for device in device_type_list:
                if device in str(message.get("sys_descr", "")).lower():
                    device_type = device
                    break
        return device_type

    def _get_snmp_command(self, oid):
        """执行采集（snmpwalk 命令行，与 agent 同款），返回 (True, 文本) 或 (False, 错误)。"""
        return _snmpwalk_command(
            self.device_ip, self.udp_port, self.snmp_version, self.community,
            self.security_level, self.security_name, self.verification_protocol,
            self.verify_password, self.privacy_protocol, self.private_key,
            oid, timeout=self.timeout,
        )

    def _split_result_str(self, s):
        split_str = ":"
        if "STRING:" in s:
            split_str = "STRING:"
        elif "Timeticks:" in s:
            split_str = "Timeticks:"
        elif "INTEGER:" in s:
            split_str = "INTEGER:"
        elif "IpAddress:" in s:
            split_str = "IpAddress:"
        elif "Counter32:" in s:
            split_str = "Counter32:"
        elif "Gauge32:" in s:
            split_str = "Gauge32:"
        return s.split(split_str)[-1].strip()

    def _get_str_result_dict(self, res):
        if isinstance(res, list) and len(res) > 0:
            return self._split_result_str(res[0])
        elif isinstance(res, str):
            return self._split_result_str(res)
        else:
            return ""

    def _get_list_result_dict(self, res):
        li = []
        if isinstance(res, list) and len(res) > 0:
            for r in res:
                li.append(self._split_result_str(r))
        elif isinstance(res, str) and len(res) > 0:
            for i in res.splitlines():
                li.append(self._split_result_str(i))
        return li

    def _turn_param_style(self, params):
        temp_dict = {}
        for name, value in params.items():
            new_name = ""
            name += " "
            for i in range(len(name) - 1):
                if i == 0:
                    new_name += name[i].lower()
                elif name[i].isupper() and name[i - 1].islower():
                    new_name += "_" + name[i].lower()
                elif name[i].isupper() and name[i - 1].isupper() and name[i + 1].islower():
                    new_name += "_" + name[i].lower()
                else:
                    new_name += name[i]
            temp_dict.update({new_name.lower(): value})
        return temp_dict

    def _get_device_oid(self, items):
        public_oid = DEVICE_OID_LIST.get("public", {}).get(items)
        if public_oid:
            return public_oid
        items_dict = DEVICE_OID_LIST.get(self.device_type) or DEVICE_OID_LIST.get("default", {})
        return items_dict.get(items, "")

    def _get_device_oid_list(self, items_list):
        return [self._get_device_oid(items) for items in items_list]

    def _get_scan_list_info(self, oids):
        dic = {}
        oid_list = self._get_device_oid_list(oids)
        try:
            for i in range(len(oids)):
                status, device_mib = self._get_snmp_command(oid_list[i])
                if not status:
                    continue
                dic[oids[i]] = self._get_list_result_dict(device_mib)
            return True, self._turn_param_style(dic)
        except Exception as e:
            return False, str(e)

    def _get_scan_str_info(self, oids):
        dic = {}
        oid_list = self._get_device_oid_list(oids)
        try:
            for i in range(len(oids)):
                status, device_mib = self._get_snmp_command(oid_list[i])
                if not status:
                    continue
                dic[oids[i]] = self._get_str_result_dict(device_mib)
            return True, self._turn_param_style(dic)
        except Exception as e:
            return False, str(e)

    def test_ping(self):
        try:
            status, device_mib = self._get_snmp_command("sysName")
            if not status:
                return False, str(device_mib)
            return True, "Success"
        except Exception as e:
            return False, str(e)

    def get_sys_descr(self):
        return self._get_scan_str_info(["sysDescr"])

    def get_if_info(self):
        oids = ["ifIndex", "ifName", "ifDescr", "ifAlias", "ifType", "ifPhysAddress",
                "ifAdminStatus", "ifOperStatus", "ifSpeed", "ifInOctets", "ifOutOctets"]
        return self._get_scan_list_info(oids)

    def get_ip_info(self):
        oids = ["ipNetToMediaIfIndex", "ipNetToMediaPhysAddress", "ipNetToMediaNetAddress",
                "ipAdEntNetMask", "ipNetToMediaType"]
        return self._get_scan_list_info(oids)

    def get_system_info(self):
        oids = ["sysName", "sysDescr", "sysLocation", "sysContact", "sysUpTime",
                "sysObjectID", "sys_version"]
        return self._get_scan_str_info(oids)

    def get_dict_result_dict(self, res, search_str_get_key=None):
        li = []
        if isinstance(res, str) and len(res) > 0:
            li = res.splitlines()
        elif isinstance(res, list) and len(res) > 0:
            li = res
        dic = {}
        for i in li:
            k, v = self._split_result_str_v2(i)
            if search_str_get_key:
                if k and search_str_get_key in v:
                    return k
            dic[k] = v
        return dic

    def _split_result_str_v2(self, s):
        split_str = ":"
        if "STRING:" in s:
            split_str = "STRING:"
        elif "Timeticks:" in s:
            split_str = "Timeticks:"
        elif "INTEGER:" in s:
            split_str = "INTEGER:"
        elif "IpAddress:" in s:
            split_str = "IpAddress:"
        elif "Counter32:" in s:
            split_str = "Counter32:"
        elif "Gauge32:" in s:
            split_str = "Gauge32:"
        split_list = s.split(split_str)
        split_1 = s.split(split_str)[-1].strip()
        split_0 = ""
        if len(split_list) >= 2:
            split_0 = str(split_list[0].split(" = ")[0].split(".")[-1]).strip()
        return split_0, split_1

    def get_cpu_info(self):
        if self.device_type == "huawei":
            return self._get_huawei_cpu_mem_info()
        return self._get_h3c_cpu_mem_info()

    def _get_h3c_cpu_mem_info(self):
        cpu, mem = 0, 0
        phy_name_oid = self._get_device_oid("entPhysicalName")
        phy_cpu_oid = self._get_device_oid("hh3cEntityExtCpuUsage_One")
        phy_cpu_oid_new = self._get_device_oid("hh3cEntityExtCpuUsage_One_new")
        phy_mem_oid = self._get_device_oid("hh3cEntityExtMemUsage_One")
        phy_mem_oid_new = self._get_device_oid("hh3cEntityExtMemUsage_One_new")
        if phy_name_oid:
            status, phy_res = self._get_snmp_command(phy_name_oid)
            if status:
                phy_name_index = self.get_dict_result_dict(phy_res, search_str_get_key="Master Board")
                status, cpu_res = self._get_snmp_command(phy_cpu_oid.format(phy_name_index))
                if not status:
                    status, cpu_res = self._get_snmp_command(phy_cpu_oid_new)
                if status:
                    cpu = self._split_result_str(cpu_res)
                status, mem_res = self._get_snmp_command(phy_mem_oid.format(phy_name_index))
                if not status:
                    status, mem_res = self._get_snmp_command(phy_mem_oid_new)
                if status:
                    mem = self._split_result_str(mem_res)
        return True, {"cpu": cpu, "mem": mem}

    def _get_huawei_cpu_mem_info(self):
        cpu, mem = 0, 0
        phy_name_oid = self._get_device_oid("entPhysicalName")
        phy_cpu_oid = self._get_device_oid("hwEntityCpuUsage")
        phy_mem_oid = self._get_device_oid("hwEntityMemUsage")
        if phy_name_oid:
            status, phy_res = self._get_snmp_command(phy_name_oid)
            if status:
                phy_name_index = self.get_dict_result_dict(phy_res, search_str_get_key="LPU Board")
                status, cpu_res = self._get_snmp_command(phy_cpu_oid.format(phy_name_index))
                if status:
                    cpu = self._split_result_str(cpu_res)
                status, mem_res = self._get_snmp_command(phy_mem_oid.format(phy_name_index))
                if status:
                    mem = self._split_result_str(mem_res)
        return True, {"cpu": cpu, "mem": mem}


# ======================================================================
# 统一本地执行入口（对齐 agent 接口的 data 返回格式）
# ======================================================================
def local_check_network_status_v3(snmp_dict, ssh_dict, telnet_dict):
    """对齐 agent check-network-status-v3：单台实时连通性测试。
    返回 {snmp_ping:{status,message}} / {ssh_ping:...} / {telnet:...}。"""
    if snmp_dict:
        return _local_snmp_ping_one(snmp_dict, "snmp_ping")
    if ssh_dict:
        return _local_ssh_ping_one(ssh_dict, "ssh_ping")
    return _local_ssh_ping_one(telnet_dict or {}, "telnet")


def _local_snmp_ping_one(dic, host):
    d = dict(dic)
    d.pop("host", None)
    d.setdefault("udp_port", 161)
    api = NetworkSnmpApi(**d)
    status, message = api.test_ping()
    return {host: {"status": status, "message": message}}


def _local_ssh_ping_one(dic, host):
    d = dict(dic)
    d.pop("host", None)
    try:
        api = NetworkSSHApi(**d)
        status, message = api.test_ping()
        api.close()
    except TypeError as e:
        status, message = False, "参数错误: {}".format(e)
    return {host: {"status": status, "message": message}}


def local_network_snmp_scan(data):
    """对齐 agent network-snmp-scan：SNMP 采集（直接传凭据）。
    返回 {ping/system/if/ip/cpu_mem: {status, data}}。"""
    d = dict(data or {})
    info_type_list = d.pop("info_type_list", "all")
    if info_type_list == "all":
        info_type_list = ["ping", "system", "if", "ip", "cpu_mem"]
    d.setdefault("udp_port", 161)
    try:
        snmp_api = NetworkSnmpApi(**d)
    except TypeError as e:
        return {"error": {"status": False, "data": "参数错误: {}".format(e)}}
    dic = {}
    if "ping" in info_type_list:
        ping_status, ping_info = snmp_api.test_ping()
        dic["ping"] = {"status": ping_status, "data": ping_info}
        if not ping_status:
            return dic
    if "system" in info_type_list:
        sys_status, sys_info = snmp_api.get_system_info()
        dic["system"] = {"status": sys_status, "data": sys_info}
    if "if" in info_type_list:
        if_status, if_info = snmp_api.get_if_info()
        dic["if"] = {"status": if_status, "data": if_info}
    if "ip" in info_type_list:
        ip_status, ip_info = snmp_api.get_ip_info()
        dic["ip"] = {"status": ip_status, "data": ip_info}
    if "cpu_mem" in info_type_list:
        cpu_status, cpu_info = snmp_api.get_cpu_info()
        dic["cpu_mem"] = {"status": cpu_status, "data": cpu_info}
    return dic


def local_network_scan_ssh(data):
    """对齐 agent network-ssh-scan：SSH/Telnet 扫描（sys_log / cpu_mem）。
    返回 {ping/cpu_mem/sys_log: {status, data}}。"""
    d = dict(data or {})
    info_type_list = d.pop("info_type_list", "all")
    if info_type_list == "all":
        info_type_list = ["sys_log"]
    try:
        ssh_api = NetworkSSHApi(**d)
    except TypeError as e:
        return {"error": {"status": False, "data": "参数错误: {}".format(e)}}
    dic = {}
    if "ping" in info_type_list:
        status, info = ssh_api.test_ping()
        dic["ping"] = {"status": status, "data": info}
    if "cpu_mem" in info_type_list:
        status, info = ssh_api.get_cpu_mem()
        dic["cpu_mem"] = {"status": status, "data": info}
    if "sys_log" in info_type_list:
        status, info = ssh_api.get_sys_log_info()
        dic["sys_log"] = {"status": status, "data": info}
    try:
        ssh_api.close()
    except Exception:
        pass
    return dic


def local_network_ssh_config(data_list):
    """对齐 agent network-ssh-config：按 host 拉取启动/运行配置。
    data_list: [{host, boot_config_script?, running_config_script?}, ...]
    返回 {host: {boot_status, run_status, boot_config_content, running_config_content, ...}}。"""
    from apps.cmdb.models.control_models import NetworkEquipmentModel
    result = {}
    for host_dict in (data_list or []):
        host = host_dict.get("host")
        if not host:
            continue
        eq = NetworkEquipmentModel.objects.filter(host=host).first()
        if not eq:
            result[host] = {"boot_status": False, "run_status": False, "message": "eSight 库中无此设备"}
            continue
        # 解密登录密码
        from apps.cmdb.api.network_views import PasswordEncryption
        pe = PasswordEncryption()
        try:
            lp = pe.decrypt(eq.login_password) if eq.login_password else ""
        except Exception:
            lp = eq.login_password or ""
        ssh_kwargs = {
            "ip": eq.ip,
            "port": int(eq.ssh_port or 22) if eq.connection_type == "SSH" else int(eq.telnet_port or 23),
            "login_username": eq.login_username or "",
            "login_password": lp,
            "device_type": eq.device_type or "",
            "connection_type": eq.connection_type or "SSH",
            "ssh_timeout": int(eq.ssh_timeout or 15),
        }
        boot_script = host_dict.get("boot_config_script")
        run_script = host_dict.get("running_config_script")
        try:
            ssh_api = NetworkSSHApi(**ssh_kwargs)
            if boot_script:
                boot_status, boot_msg = ssh_api.get_boot_config(boot_script)
            else:
                boot_status, boot_msg = False, "启动配置命令为空"
            if run_script:
                run_status, run_msg = ssh_api.get_run_config(run_script)
            else:
                run_status, run_msg = False, "运行配置命令为空"
            ssh_api.close()
        except TypeError as e:
            result[host] = {"boot_status": False, "run_status": False, "message": "参数错误: {}".format(e)}
            continue
        entry = {"boot_status": boot_status, "run_status": run_status}
        if boot_status and isinstance(boot_msg, dict):
            entry.update(boot_msg)
        elif not boot_status:
            entry["message"] = str(boot_msg)[:200]
        if run_status and isinstance(run_msg, dict):
            entry.update(run_msg)
        elif not run_status:
            entry["message"] = str(run_msg)[:200]
        result[host] = entry
    return result


def local_test_ping():
    """对齐 agent ht/：本地执行器恒可用。"""
    return True, "Success"


def local_create_or_update_network(res_list):
    """本地模式无需同步 agent 库（eSight 本身就是设备库）。"""
    return True, {"update_list": [], "create_list": []}


# 本地执行器能力路由表：api_path 尾段 → 调用函数
LOCAL_API_ROUTES = {
    "ht/": local_test_ping,
    "check-network-status-v3/": None,  # 特殊处理（三个 dict 参数）
    "network-snmp-scan/": None,        # 特殊处理
    "network-ssh-scan/": None,         # 特殊处理
    "network-ssh-config/": None,       # 特殊处理
    "network-equipment/": local_create_or_update_network,
}
