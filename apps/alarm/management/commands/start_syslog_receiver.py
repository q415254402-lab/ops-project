# -*- coding: utf-8 -*-
"""
Syslog 接收器 (UDP 514)

以 Django management command 形式常驻，接收 RFC3164 Syslog 报文并交给
apps.alarm.tasks.receiver.process_syslog 写入告警库。
"""
import logging
import re
import socket

from django.conf import settings
from django.core.management.base import BaseCommand

logger = logging.getLogger('esight.alarm')

# RFC3164 PRI 数值 -> eSight 严重等级
_SEVERITY_MAP = {
    0: 'critical', 1: 'critical', 2: 'critical', 3: 'major',
    4: 'warning', 5: 'info', 6: 'info', 7: 'info',
}
_SEV_NAMES = ['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug']


def parse_syslog(data):
    """解析 RFC3164 syslog，返回 (消息文本, 严重等级)"""
    text = data.decode('utf-8', 'replace').strip()
    severity = 'warning'
    m = re.match(r'<(\d+)>', text)
    if m:
        pri = int(m.group(1))
        level = pri & 7
        severity = _SEVERITY_MAP.get(level, 'warning')
    return text, severity


class Command(BaseCommand):
    help = '启动 Syslog 接收器 (UDP 514)'

    def handle(self, *args, **options):
        from apps.alarm.tasks.receiver import process_syslog

        syslog_port = int(getattr(settings, 'ESIGHT_CONFIG', {}).get('SYSLOG_PORT', 514))

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(('0.0.0.0', syslog_port))
        except Exception as exc:
            self.stderr.write(
                f'无法绑定 UDP {syslog_port}（可能需要 root/管理员权限，'
                f'且端口未被占用）: {exc}')
            raise

        self.stdout.write(f'Syslog 接收器已启动，监听 UDP {syslog_port}')
        logger.info(f'Syslog 接收器已启动，监听 UDP {syslog_port}')

        while True:
            try:
                data, addr = sock.recvfrom(8192)
            except KeyboardInterrupt:
                break
            src_ip = addr[0]
            text, severity = parse_syslog(data)
            self.stdout.write(f'[Syslog] from {src_ip}: {text[:120]}')
            try:
                process_syslog(text, src_ip)
            except Exception as exc:
                logger.error(f'处理 Syslog 失败: {exc}')

        sock.close()
