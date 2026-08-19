# -*- coding: utf-8 -*-
"""
WAF 攻击日志 Syslog UDP 接收器（2026-08-17）
启动方式（独立进程，避免 uwsgi 多 worker 重复接收）：
  python manage.py waf_syslog --host 0.0.0.0 --port 5514
supervisor 配置参考（apps 目录）：
  [program:esight_waf_syslog]
  command=python manage.py waf_syslog --port 5514
  directory=/opt/opsany/paas-agent/apps/projects/esight/code/esight
  autostart=true
  autorestart=true
  stdout_logfile=/opt/opsany/paas-agent/apps/projects/esight/logs/waf_syslog.log
"""
import logging
import socket
import threading

from django.core.management.base import BaseCommand

from apps.cmdb.models import WafAttackLog
from apps.cmdb.services.waf_syslog import parse_syslog_line

logger = logging.getLogger('app')


class Command(BaseCommand):
    help = '启动安全设备日志 Syslog UDP 接收器（WAF/防火墙通用）'

    def add_arguments(self, parser):
        parser.add_argument('--host', default='0.0.0.0')
        parser.add_argument('--port', type=int, default=5514)
        parser.add_argument('--device-type', default='WAF')
        # 过滤规则（2026-08-17 华为防火墙）：abstract 字段前缀白名单，逗号分隔；命中才保留
        # 例：--keep-prefix IPS/,DLP/,URL/  → 只收 IPS/DLP/URL 类，丢弃 POLICY/SECLOG 等流量日志
        parser.add_argument('--keep-prefix', default='')

    def handle(self, *args, **options):
        host = options['host']
        port = options['port']
        device_type = options['device_type']
        keep_prefix = [p.strip().rstrip('/') + '/' for p in (options['keep_prefix'] or '').split(',') if p.strip()]
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        self.stdout.write(self.style.SUCCESS(
            f'[waf_syslog] UDP {host}:{port} 监听中 device_type={device_type} keep_prefix={keep_prefix or "全部"}'))
        while True:
            try:
                data, addr = sock.recvfrom(65535)
            except OSError as e:
                logger.error('recvfrom error: %s', e)
                continue
            try:
                text = data.decode('utf-8', errors='replace').strip()
                item = parse_syslog_line(text)
                if not item:
                    logger.debug('无法解析: %s', text[:200])
                    continue
                # 2026-08-17：华为防火墙过滤——abstract 字段前缀命中才保留（IPS/DLP/URL 安全事件）
                abstract = item.pop('abstract', '') or ''
                if keep_prefix:
                    if not any(abstract.startswith(p) for p in keep_prefix):
                        continue
                log_time = item.pop('log_time', None)
                obj = WafAttackLog(**item, device_type=device_type)
                if log_time:
                    obj.log_time = log_time
                obj.save()
                logger.info('[waf_syslog] %s -> %s %s from %s',
                            obj.src_ip or '-', obj.dst_ip or '-',
                            obj.event_type or '-', addr[0])
            except Exception as e:
                logger.error('parse/save error: %s', e)
