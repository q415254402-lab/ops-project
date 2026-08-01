"""
SSH 采集器 — 用于服务器和网络设备的 SSH 采集
"""
import re
import logging
import paramiko

from .base import BaseCollector

logger = logging.getLogger('esight.collector.ssh')


class SSHCollector(BaseCollector):
    """SSH 采集器"""

    def __init__(self, ip_address, credential=None, port=22, timeout=10, retries=2):
        super().__init__(ip_address, credential, timeout, retries)
        self.port = port
        self._client = None

    def connect(self):
        """建立 SSH 连接"""
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        cred = self.credential
        connect_kwargs = {
            'hostname': self.ip_address,
            'port': self.port or 22,
            'timeout': self.timeout,
        }

        if cred:
            if cred.ssh_key:
                import io
                key_file = io.StringIO(cred.ssh_key)
                pkey = paramiko.RSAKey.from_private_key(key_file, password=cred.password or None)
                connect_kwargs['pkey'] = pkey
            else:
                connect_kwargs['username'] = cred.username
                connect_kwargs['password'] = cred.password
        else:
            connect_kwargs['username'] = 'admin'
            connect_kwargs['password'] = ''

        self._client.connect(**connect_kwargs)
        self._connected = True
        logger.info(f'SSH 连接建立: {self.ip_address}:{self.port}')

    def disconnect(self):
        """断开 SSH 连接"""
        if self._client:
            self._client.close()
        self._connected = False
        logger.debug(f'SSH 连接断开: {self.ip_address}')

    def execute_command(self, command, timeout=30):
        """执行 SSH 命令"""
        if not self._connected:
            raise ConnectionError('SSH 未连接')
        stdin, stdout, stderr = self._client.exec_command(command, timeout=timeout)
        output = stdout.read().decode('utf-8', errors='ignore')
        error = stderr.read().decode('utf-8', errors='ignore')
        exit_code = stdout.channel.recv_exit_status()
        return output, error, exit_code

    def get_system_info(self):
        """获取系统信息 (Linux 服务器)"""
        info = {}
        try:
            # Hostname
            output, _, _ = self.execute_command('hostname')
            info['hostname'] = output.strip()

            # OS Version
            output, _, _ = self.execute_command('cat /etc/os-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null')
            info['os_version'] = output.strip()

            # Kernel
            output, _, _ = self.execute_command('uname -r')
            info['kernel'] = output.strip()

            # Uptime
            output, _, _ = self.execute_command('uptime -s 2>/dev/null || uptime')
            info['uptime'] = output.strip()

        except Exception as e:
            logger.error(f'获取系统信息失败: {self.ip_address} - {e}')
        return info

    def get_cpu_info(self):
        """获取 CPU 信息"""
        try:
            # CPU 使用率 (top 一次)
            output, _, _ = self.execute_command(
                "top -bn1 | grep 'Cpu(s)' | awk '{print $2}' 2>/dev/null || "
                "vmstat 1 2 | tail -1 | awk '{print 100-$15}'"
            )
            usage = self._safe_float(output.strip())

            # 负载
            output, _, _ = self.execute_command("cat /proc/loadavg")
            parts = output.strip().split()
            load_1 = self._safe_float(parts[0]) if len(parts) > 0 else 0
            load_5 = self._safe_float(parts[1]) if len(parts) > 1 else 0
            load_15 = self._safe_float(parts[2]) if len(parts) > 2 else 0

            return {
                'usage_percent': usage,
                'load_1': load_1,
                'load_5': load_5,
                'load_15': load_15,
            }
        except Exception as e:
            logger.error(f'获取 CPU 信息失败: {self.ip_address} - {e}')
            return {}

    def get_memory_info(self):
        """获取内存信息"""
        try:
            output, _, _ = self.execute_command("free -m | grep Mem")
            parts = output.strip().split()
            total = self._safe_int(parts[1]) if len(parts) > 1 else 0
            used = self._safe_int(parts[2]) if len(parts) > 2 else 0
            usage = (used / total * 100) if total > 0 else 0
            return {
                'total_mb': total,
                'used_mb': used,
                'usage_percent': round(usage, 2),
            }
        except Exception as e:
            logger.error(f'获取内存信息失败: {self.ip_address} - {e}')
            return {}

    def get_disk_info(self):
        """获取磁盘信息"""
        try:
            output, _, _ = self.execute_command("df -h | grep -v tmpfs | grep -v devtmpfs")
            disks = []
            for line in output.strip().split('\n')[1:]:
                parts = line.split()
                if len(parts) >= 6:
                    disks.append({
                        'mount_point': parts[5],
                        'total': parts[1],
                        'used': parts[2],
                        'available': parts[3],
                        'usage_percent': self._safe_float(parts[4].replace('%', '')),
                    })
            return disks
        except Exception as e:
            logger.error(f'获取磁盘信息失败: {self.ip_address} - {e}')
            return []

    def get_network_config(self):
        """获取网络配置"""
        try:
            output, _, _ = self.execute_command("ip -o addr show | grep 'inet '")
            interfaces = []
            for line in output.strip().split('\n'):
                match = re.search(r'(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', line)
                if match:
                    interfaces.append({
                        'name': match.group(1),
                        'ip_address': match.group(2),
                        'mask': match.group(3),
                    })
            return interfaces
        except Exception as e:
            logger.error(f'获取网络配置失败: {self.ip_address} - {e}')
            return []

    def get_custom_command(self, command):
        """执行自定义命令"""
        output, error, exit_code = self.execute_command(command)
        return {
            'output': output,
            'error': error,
            'exit_code': exit_code,
        }
