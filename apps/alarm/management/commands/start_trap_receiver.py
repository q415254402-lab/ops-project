# -*- coding: utf-8 -*-
"""
SNMP Trap 接收器 (UDP 162)

以 Django management command 形式常驻，接收 SNMP Trap 并交给
apps.alarm.tasks.receiver.process_trap 写入告警库。
"""
import logging

from django.conf import settings
from django.core.management.base import BaseCommand

logger = logging.getLogger('esight.alarm')


class Command(BaseCommand):
    help = '启动 SNMP Trap 接收器 (UDP 162)'

    def handle(self, *args, **options):
        from pysnmp.entity import engine as snmp_engine_mod
        from pysnmp.entity import config as snmp_config
        from pysnmp.carrier.asyncore.dgram import udp
        from pysnmp.entity.rfc3413 import ntfrcv
        from apps.alarm.tasks.receiver import process_trap

        trap_port = int(getattr(settings, 'ESIGHT_CONFIG', {}).get('TRAP_PORT', 162))

        snmp_engine = snmp_engine_mod.SnmpEngine()

        def handle_trap(snmp_engine, state_reference, context_engine_id, context_name,
                        var_binds, cb_ctx):
            try:
                exec_ctx = snmp_engine.observer.getExecutionContext(
                    'rfc3412.receiveMessage:request')
                src_ip = exec_ctx['transportAddress'][0]
            except Exception:
                src_ip = '0.0.0.0'

            oids = {}
            for oid, val in var_binds:
                try:
                    oids[str(oid)] = val.pretty()
                except Exception:
                    oids[str(oid)] = str(val)

            trap_data = {'source_ip': src_ip, 'oids': oids}
            self.stdout.write(f'[Trap] from {src_ip}: {list(oids.items())[:3]}')
            try:
                process_trap(trap_data)
            except Exception as exc:
                logger.error(f'处理 Trap 失败: {exc}')

        try:
            snmp_config.addTransport(
                snmp_engine, udp.domainName,
                udp.UdpTransport().openServerMode(('0.0.0.0', trap_port)))
            snmp_config.addV1System(snmp_engine, 'public', 'public')
            ntfrcv.NotificationReceiver(snmp_engine, handle_trap)
        except Exception as exc:
            self.stderr.write(
                f'无法绑定 UDP {trap_port}（可能需要 root/管理员权限，'
                f'且端口未被占用）: {exc}')
            raise

        self.stdout.write(f'SNMP Trap 接收器已启动，监听 UDP {trap_port}')
        logger.info(f'SNMP Trap 接收器已启动，监听 UDP {trap_port}')
        snmp_engine.transportDispatcher.jobStarted(1)
        try:
            snmp_engine.transportDispatcher.runDispatcher()
        except KeyboardInterrupt:
            pass
        finally:
            snmp_engine.transportDispatcher.closeDispatcher()
