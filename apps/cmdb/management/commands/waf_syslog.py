# -*- coding: utf-8 -*-
"""
WAF 攻击日志 Syslog UDP 接收器（2026-08-19 v2：抗丢包 + CPU 保护）
启动方式（独立进程，避免 uwsgi 多 worker 重复接收）：
  python manage.py waf_syslog --host 0.0.0.0 --port 5514
  python manage.py waf_syslog --port 5515 --device-type Firewall --keep-prefix IPS/,URL/

v2 关键改动（2026-08-19，根因：RcvbufErrors 93.8 万条 UDP 丢包）：
  1. 快速预过滤前置：完整正则解析前先用 '%%01IPS/' 等轻量 in 判断，
     跳过 99.9% 无用 POLICY 流量日志的解析，释放 CPU 给真正的攻击日志
  2. 批量入库：接收线程入队 + 后台线程 bulk_create（~100 条/批），
     消除逐条 DB save() 同步写盘阻塞接收循环
  3. SO_RCVBUF 调大（默认 8MB，需内核 net.core.rmem_max 配合，见上线侧）
  4. CPU 保护：select 50ms 超时让出 CPU + 有界队列背压限速 + 进程 CPU 自检，
     超 --cpu-max（默认 70%）自动加大背压，保证空闲≈0%、洪峰不打满
  5. 周期统计日志：收包/过滤丢弃/队列丢弃/解析失败/CPU%，便于核对数量

supervisor 配置参考（apps 目录）：
  [program:esight_waf_syslog]
  command=python manage.py waf_syslog --port 5514
  directory=/opt/opsany/paas-agent/apps/projects/esight/code/esight
  autostart=true
  autorestart=true
  stdout_logfile=/opt/opsany/paas-agent/apps/projects/esight/logs/waf_syslog.log
"""
import logging
import os
import queue
import select
import socket
import threading
import time

from django.core.management.base import BaseCommand
from django.utils import timezone as dj_timezone

from apps.cmdb.models import WafAttackLog
from apps.cmdb.services.waf_syslog import parse_syslog_line

logger = logging.getLogger('app')

QUEUE_MAX = 5000          # 有界队列上限（背压阈值）
BATCH_SIZE = 100          # 批量入库条数
FLUSH_INTERVAL = 0.2      # 最长积压时间（秒）
STAT_INTERVAL = 60        # 统计日志周期（秒）
SELECT_TIMEOUT = 0.05     # select 超时（秒），空闲时让出 CPU
BACKOFF_BASE = 0.005      # 背压基础 sleep（秒）
BACKOFF_MAX = 0.05        # CPU 超限时的最大背压 sleep（秒）


def _read_proc_stat():
    """读取 /proc/self/stat，返回 (utime, stime, starttime) jiffies"""
    try:
        with open('/proc/self/stat') as f:
            data = f.read()
        idx = data.rfind(')')
        fields = data[idx + 2:].split()  # 从 state 开始
        # 原字段: state(3) ppid(4) ... utime(14) stime(15) ... starttime(22)
        # fields[0]=state → utime=fields[11] stime=fields[12] starttime=fields[19]
        return (int(fields[11]), int(fields[12]), int(fields[19]))
    except Exception:
        return (0, 0, 0)


class Command(BaseCommand):
    help = '启动安全设备日志 Syslog UDP 接收器（WAF/防火墙通用，v2 抗丢包+CPU保护）'

    def add_arguments(self, parser):
        parser.add_argument('--host', default='0.0.0.0')
        parser.add_argument('--port', type=int, default=5514)
        parser.add_argument('--device-type', default='WAF')
        # 过滤规则（2026-08-17 华为防火墙）：abstract 字段前缀白名单，逗号分隔；命中才保留
        # 例：--keep-prefix IPS/,DLP/,URL/  → 只收 IPS/DLP/URL 类，丢弃 POLICY/SECLOG 等流量日志
        parser.add_argument('--keep-prefix', default='')
        # v2：接收缓冲区大小（MB），受内核 net.core.rmem_max 限制
        parser.add_argument('--rcvbuf-mb', type=int, default=8)
        # v2：CPU 上限（%），超限自动加大背压限速，保证系统保留 30% 余量
        parser.add_argument('--cpu-max', type=float, default=70.0)

    def handle(self, *args, **options):
        host = options['host']
        port = options['port']
        device_type = options['device_type']
        cpu_max = options['cpu_max']
        rcvbuf = options['rcvbuf_mb'] * 1024 * 1024
        keep_prefix = [p.strip().rstrip('/') + '/' for p in (options['keep_prefix'] or '').split(',') if p.strip()]
        # 快速预过滤用前缀（华为 syslog 格式：%%01IPS/4/DETECT）
        quick_prefixes = ['%%01' + p for p in keep_prefix]

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        actual_rcvbuf = 0
        if rcvbuf > 0:
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
                actual_rcvbuf = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            except OSError as e:
                logger.warning('SO_RCVBUF 设置失败（内核 rmem_max 可能过小）: %s', e)
        sock.bind((host, port))

        # 有界队列 + 后台批量入库线程
        q = queue.Queue(maxsize=QUEUE_MAX)
        ctl = {'backoff': BACKOFF_BASE}
        threading.Thread(target=self._writer_loop, args=(q, device_type), daemon=True).start()

        stats = {'recv': 0, 'filter_drop': 0, 'queue_drop': 0, 'parse_fail': 0, 'url_drop': 0}
        last_stat = time.time()
        last_cpu = _read_proc_stat()
        hz = os.sysconf('SC_CLK_TCK') or 100

        self.stdout.write(self.style.SUCCESS(
            f'[waf_syslog v2] UDP {host}:{port} 监听中 device_type={device_type} '
            f'keep_prefix={keep_prefix or "全部"} rcvbuf={actual_rcvbuf}B cpu_max={cpu_max}%'))
        while True:
            try:
                r, _, _ = select.select([sock], [], [], SELECT_TIMEOUT)
                if not r:
                    continue
                data, addr = sock.recvfrom(65535)
            except OSError as e:
                logger.error('recvfrom error: %s', e)
                continue
            stats['recv'] += 1
            try:
                text = data.decode('utf-8', errors='replace').strip()
                if not text:
                    continue
                # v2 快速预过滤：完整解析前先轻量判断，跳过 99.9% 无用流量日志
                if quick_prefixes and not any(p in text for p in quick_prefixes):
                    stats['filter_drop'] += 1
                    continue
                item = parse_syslog_line(text)
                if not item:
                    stats['parse_fail'] += 1
                    continue
                # 2026-08-24：不再采集「URL过滤」类日志（event_type 含 url，与前端 typeText 归类一致）
                if 'url' in (item.get('event_type') or '').lower():
                    stats['url_drop'] += 1
                    continue
                # 精确过滤（v1 逻辑保留，防止快速预过滤误命中）
                abstract = item.pop('abstract', '') or ''
                if keep_prefix:
                    if not any(abstract.startswith(p) for p in keep_prefix):
                        stats['filter_drop'] += 1
                        continue
                # 入队（有界；队列满 → 背压限速，防止 CPU 打满 + 内核缓冲溢出）
                try:
                    q.put_nowait(item)
                except queue.Full:
                    stats['queue_drop'] += 1
                    time.sleep(ctl['backoff'])
            except Exception as e:
                logger.error('parse error: %s', e)

            # 周期统计 + CPU 自检
            if time.time() - last_stat >= STAT_INTERVAL:
                now_cpu = _read_proc_stat()
                dt = time.time() - last_stat
                dcpu = (now_cpu[0] - last_cpu[0]) + (now_cpu[1] - last_cpu[1])
                cpu_pct = (dcpu / (dt * hz)) * 100.0 if dt > 0 else 0.0
                if cpu_pct > cpu_max:
                    ctl['backoff'] = min(ctl['backoff'] * 2, BACKOFF_MAX)
                else:
                    ctl['backoff'] = BACKOFF_BASE
                self.stdout.write(
                    f'[waf_syslog] {port} recv={stats["recv"]} filter_drop={stats["filter_drop"]} '
                    f'url_drop={stats["url_drop"]} queue_drop={stats["queue_drop"]} parse_fail={stats["parse_fail"]} '
                    f'cpu={cpu_pct:.1f}% backoff={ctl["backoff"]:.3f}s qsize={q.qsize()}')
                stats = {'recv': 0, 'filter_drop': 0, 'queue_drop': 0, 'parse_fail': 0, 'url_drop': 0}
                last_cpu = now_cpu
                last_stat = time.time()

    def _writer_loop(self, q, device_type):
        """后台批量入库线程：积够 BATCH_SIZE 或超过 FLUSH_INTERVAL 就 bulk_create"""
        batch = []
        last_flush = time.time()
        while True:
            try:
                item = q.get(timeout=0.1)  # 100ms 超时，空闲时让出 CPU
            except queue.Empty:
                if batch and (time.time() - last_flush) >= FLUSH_INTERVAL:
                    self._flush(batch, device_type)
                    batch = []
                    last_flush = time.time()
                continue
            batch.append(item)
            if len(batch) >= BATCH_SIZE or (time.time() - last_flush) >= FLUSH_INTERVAL:
                self._flush(batch, device_type)
                batch = []
                last_flush = time.time()

    def _flush(self, batch, device_type):
        """批量落库（单条坏日志跳过不影响整批；失败仅记日志不重试防堆积）"""
        if not batch:
            return
        objs = []
        skipped = 0
        for item in batch:
            try:
                log_time = item.pop('log_time', None)
                obj = WafAttackLog(**item, device_type=device_type)
                # log_time 必填兜底：缺省用当前时间，避免单条坏日志连累整批
                obj.log_time = log_time or dj_timezone.now()
                objs.append(obj)
            except Exception:
                skipped += 1
        if not objs:
            logger.error('[waf_syslog] batch 全部构造失败，%d 条丢弃', len(batch))
            return
        try:
            WafAttackLog.objects.bulk_create(objs)
            if skipped:
                logger.warning('[waf_syslog] batch saved %d, skipped %d 条坏日志', len(objs), skipped)
            else:
                logger.info('[waf_syslog] batch saved %d', len(objs))
        except Exception as e:
            logger.error('bulk save error (%d 条丢弃): %s', len(objs), e)
