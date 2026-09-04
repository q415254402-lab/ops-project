# -*- coding: utf-8 -*-
"""
系统漏洞同步服务（vScan vullogsystem → 本地 DB，2026-08-26）
镜像 WEB 漏洞 vscan_web_sync.py：懒检测 / 触发同步 / 状态查询。
读取全走 VscanVuln 表（秒开）；慢速上游仅在后台同步线程调用。

与 WEB 的区别：
  - check_new_report 纯 DB 查询（不调上游）→ 即时返回；新鲜判定 = DB 有数据且同步时间在窗口内
  - 数据是单一当前快照：每次同步全量替换（delete + bulk_create），无需按 taskid 分桶
  - 任务概要（task_total/running/finished）在同步时顺带拉一次，存入 meta 供 stats 读取
"""
import json
import logging
import os
import time
import threading
from datetime import timedelta

from django.db.models import Max
from django.utils import timezone

from apps.cmdb.models import VscanVuln
from apps.cmdb.services.vscan_client import (
    get_client, cache_get_meta, cache_set_meta, cache_lock, fcntl,
)

logger = logging.getLogger('app')

SYNC_META_KEY = 'vuln_sync'
# 同步锁超时（秒）：超过此时间仍 building 视为失效，调用方应重新触发
BUILDING_TTL = int(os.environ.get('VSCAN_BUILDING_TTL', '600'))
# 新鲜窗口（小时）：DB 同步时间在窗口内视为 fresh（无需重新拉上游）
FRESH_HOURS = int(os.environ.get('VSCAN_SYS_FRESH_HOURS', '24'))


def _is_building(meta):
    """meta 处于同步中且未超时返回 True；超时视为失效，调用方应重新触发。"""
    if not meta or not meta.get('building'):
        return False
    return (time.time() - meta.get('ts', 0)) < BUILDING_TTL


def check_new_report():
    """懒检测：DB 是否有数据且新鲜（同步时间在 FRESH_HOURS 内）
    返回 {'fresh': bool, 'db_vuln_total': int, 'latest_sync': str}
    ⚠️ 纯 DB 查询，不调上游 → 即时返回（区别于 WEB 的 taskid 比对，WEB 需打 queryindex）
    """
    try:
        cnt = VscanVuln.objects.count()
        if cnt == 0:
            return {'fresh': False, 'db_vuln_total': 0, 'latest_sync': ''}
        latest = VscanVuln.objects.aggregate(m=Max('sync_time'))['m']
        fresh = bool(latest and (timezone.now() - latest < timedelta(hours=FRESH_HOURS)))
        return {
            'fresh': fresh,
            'db_vuln_total': cnt,
            'latest_sync': latest.strftime('%Y-%m-%d %H:%M:%S') if latest else '',
        }
    except Exception as e:
        logger.exception('[vscan-sys-sync] check_new_report error')
        return {'fresh': False, 'db_vuln_total': 0, 'err': str(e)}


def sync_trigger():
    """触发同步：已是最新 → 返回 fresh；否则启动后台同步线程
    返回 {'building': bool, 'fresh': bool, ...}
    """
    meta = cache_get_meta(SYNC_META_KEY)
    if _is_building(meta):
        return {'building': True, 'fresh': False, **meta}
    check = check_new_report()
    if check.get('fresh'):
        return {'building': False, 'fresh': True, 'db_vuln_total': check.get('db_vuln_total')}
    # 触发后台同步（线程，不阻塞请求）
    t = threading.Thread(target=sync_all, daemon=True)
    t.start()
    return {'building': True, 'fresh': False, 'db_vuln_total': check.get('db_vuln_total')}


def sync_status():
    """同步状态（供前端轮询）"""
    meta = cache_get_meta(SYNC_META_KEY)
    if not meta:
        return {'building': False, 'done': True, 'msg': '未开始'}
    return meta


def sync_all():
    """全量同步系统漏洞落库（后台线程，不阻塞请求）
    分页拉 vullogsystem/queryplugin 全量 → Python 去重 → 全量替换 VscanVuln 表
    → 顺带拉 task_list 存任务概要到 meta（供 stats 读取，避免读路径打上游）
    """
    lock = cache_lock(SYNC_META_KEY)
    try:
        # 双检：可能别的 worker 正在同步
        meta = cache_get_meta(SYNC_META_KEY)
        if _is_building(meta):
            return
        client = get_client()
        cache_set_meta(SYNC_META_KEY, {
            'building': True, 'done_tasks': 0, 'total_tasks': 1,
            'current_task': '系统漏洞', 'msg': '开始同步', 'ts': time.time(), 'err': '',
        })
        try:
            vulns = _fetch_vulns_no_cache(client)
        except Exception as e:
            logger.exception('[vscan-sys-sync] 拉取失败')
            cache_set_meta(SYNC_META_KEY, {
                'building': False, 'done': True, 'msg': '同步失败: %s' % e,
                'ts': time.time(), 'err': str(e),
            })
            return

        high_total = sum(1 for v in vulns if str(v.get('severity')) in ('3', '4'))

        # 全量替换（当前快照语义）
        VscanVuln.objects.all().delete()

        def _bulk(objs):
            try:
                VscanVuln.objects.bulk_create(objs, batch_size=500, ignore_conflicts=True)
            except Exception:
                # 老版本 SQLite 不支持 ON CONFLICT（<3.24）→ 降级顺序插入
                for o in objs:
                    try:
                        o.save()
                    except Exception:
                        pass

        if vulns:
            _bulk([VscanVuln(
                asset_group=v.get('asset_group') or '',
                asset_name=v.get('asset_name') or '',
                ip=v.get('ip') or '',
                admin=v.get('admin') or '',
                os=v.get('os') or '',
                severity=int(v.get('severity') or 0),
                name=v.get('name') or '',
                port=str(v.get('port') or ''),
                time=v.get('time') or '',
                rid=str(v.get('rid') or ''),
                detail=json.dumps(v.get('detail') or {}, ensure_ascii=False),
            ) for v in vulns])

        # 任务概要（task_list 单次 ~0.5s，仅供 stats 展示，不阻塞读路径）
        task_summary = {}
        try:
            tasks = client.task_list()
            task_summary = {
                'task_total': len(tasks),
                'task_running': sum(1 for t in tasks if t.get('status') in (1, 2, 6)),
                'task_finished': sum(1 for t in tasks if t.get('status') in (3, 4)),
            }
        except Exception as e:
            logger.warning('[vscan-sys-sync] task_list 拉取失败（stats 任务数将置 0）: %s', e)

        cache_set_meta(SYNC_META_KEY, {
            'building': False, 'done': True, 'done_tasks': 1, 'total_tasks': 1,
            'current_task': '', 'msg': '同步完成（%d 条漏洞）' % len(vulns),
            'ts': time.time(), 'err': '',
            'task_total': task_summary.get('task_total', 0),
            'task_running': task_summary.get('task_running', 0),
            'task_finished': task_summary.get('task_finished', 0),
            'vuln_total': len(vulns), 'high_total': high_total,
        })
        logger.info('[vscan-sys-sync] 同步完成 %d 条漏洞（高危 %d）', len(vulns), high_total)
    finally:
        if lock and fcntl is not None:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        if lock:
            lock.close()


def _fetch_vulns_no_cache(client):
    """分页拉全量系统漏洞（vullogsystem/queryplugin），按 (asset_name, ip, name, port) 去重"""
    out = []
    seen = set()
    start = 0
    while True:
        res = client.vuln_list(None, length=500, start=start)
        rows = res.get('data') or []
        if not rows:
            break
        for r in rows:
            key = (str(r.get('asset_name')), str(r.get('ip')), str(r.get('name')), str(r.get('port')))
            if key in seen:
                continue
            seen.add(key)
            out.append(r)
        if len(rows) < 500:
            break
        start += 500
    return out
