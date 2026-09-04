# -*- coding: utf-8 -*-
"""
WEB 漏洞同步服务（vScan → 本地 DB，2026-08-22）
目的：①查询秒开（不再实时拉 vScan 62s）②整改对比（多报告 diff）③60 天滚动清理

同步策略：
  1. 懒检测：DB 最新 taskid vs vScan queryindex 第一条（= 最新报告）
  2. 全量同步：逐任务串行（防 vScan 并发互踢），每任务先删旧再 bulk_create（快照一致性）
  3. 60 天清理：同步完成后删除 60 天前的 Task/Site/Vuln
  4. 文件锁 + 状态 meta（vscan_cache/web_sync.meta）防并发同步、供前端轮询
"""
import logging
import os
import time
import threading

from django.utils import timezone
from datetime import timedelta

from apps.cmdb.models import VscanWebTask, VscanWebSite, VscanWebVuln
from apps.cmdb.services.vscan_client import get_report_client, cache_get_meta, cache_set_meta, cache_lock, fcntl

logger = logging.getLogger('app')

SYNC_META_KEY = 'web_sync'
KEEP_DAYS = 60  # 60 天滚动保留

# 构建/同步锁超时（秒）：超过此时间仍 building 视为失效，调用方应重新触发。
# 防 uwsgi restart 在同步中途杀线程导致 meta 永久 building=true 卡死。
BUILDING_TTL = int(os.environ.get('VSCAN_BUILDING_TTL', '600'))


def _is_building(meta):
    """meta 处于同步中且未超时返回 True；超时视为失效，调用方应重新触发。"""
    if not meta or not meta.get('building'):
        return False
    return (time.time() - meta.get('ts', 0)) < BUILDING_TTL


def check_new_report():
    """懒检测：vScan 最新任务（queryindex 第一条）vs DB 是否已同步
    返回 {'fresh': bool, 'latest_taskid': int|None, 'db_latest_taskid': int|None}
    """
    try:
        client = get_report_client()
        vscan_tasks = client.web_tasks(desc=True)  # 第一条 = 最新报告
        if not vscan_tasks:
            return {'fresh': True, 'latest_taskid': None, 'db_latest_taskid': None}
        latest = vscan_tasks[0]['taskid']
        db_latest = VscanWebTask.objects.order_by('-taskid').values_list('taskid', flat=True).first()
        return {
            'fresh': db_latest == latest,
            'latest_taskid': latest,
            'db_latest_taskid': db_latest,
        }
    except Exception as e:
        logger.exception('[vscan-sync] check_new_report error')
        return {'fresh': True, 'latest_taskid': None, 'db_latest_taskid': None, 'err': str(e)}


def sync_trigger():
    """触发同步：已是最新 → 返回 fresh；否则启动后台同步线程
    返回 {'building': bool, 'fresh': bool, ...}
    """
    meta = cache_get_meta(SYNC_META_KEY)
    if _is_building(meta):
        return {'building': True, 'fresh': False, **meta}
    check = check_new_report()
    if check.get('fresh'):
        return {'building': False, 'fresh': True, 'latest_taskid': check.get('latest_taskid'),
                'db_latest_taskid': check.get('db_latest_taskid')}
    # 触发后台同步（线程，不阻塞请求）
    t = threading.Thread(target=sync_all, daemon=True)
    t.start()
    return {'building': True, 'fresh': False, 'latest_taskid': check.get('latest_taskid'),
            'db_latest_taskid': check.get('db_latest_taskid')}


def sync_status():
    """同步状态（供前端轮询）"""
    meta = cache_get_meta(SYNC_META_KEY)
    if not meta:
        return {'building': False, 'done': True, 'msg': '未开始'}
    return meta


def sync_all():
    """全量同步所有任务（漏洞 + 网站）落库 + 60 天清理（串行防互踢）"""
    lock = cache_lock(SYNC_META_KEY)
    try:
        # 双检：可能别的 worker 正在同步
        meta = cache_get_meta(SYNC_META_KEY)
        if _is_building(meta):
            return
        client = get_report_client()
        tasks = client.web_tasks(desc=True)
        if not tasks:
            cache_set_meta(SYNC_META_KEY, {'building': False, 'done': True, 'msg': 'vScan 无任务',
                                           'ts': time.time(), 'err': ''})
            return
        total = len(tasks)
        cache_set_meta(SYNC_META_KEY, {'building': True, 'done_tasks': 0, 'total_tasks': total,
                                       'current_task': '', 'msg': '开始同步', 'ts': time.time(), 'err': ''})
        done = 0
        for t in tasks:
            tid = t['taskid']
            name = t['name'] or ('任务 %s' % tid)
            cache_set_meta(SYNC_META_KEY, {'building': True, 'done_tasks': done, 'total_tasks': total,
                                           'current_task': name, 'msg': '同步中: %s' % name,
                                           'ts': time.time(), 'err': ''})
            try:
                _sync_one_task(client, tid, name)
            except Exception as e:
                logger.exception('[vscan-sync] 任务 %s 同步失败', tid)
                cache_set_meta(SYNC_META_KEY, {'building': True, 'done_tasks': done, 'total_tasks': total,
                                               'current_task': name, 'msg': '失败: %s' % e,
                                               'ts': time.time(), 'err': str(e)})
            done += 1
        _cleanup_old()
        cache_set_meta(SYNC_META_KEY, {'building': False, 'done': True, 'done_tasks': done,
                                       'total_tasks': total, 'current_task': '',
                                       'msg': '同步完成（%d 个任务）' % done,
                                       'ts': time.time(), 'err': ''})
        logger.info('[vscan-sync] 同步完成 %d 个任务', done)
    finally:
        if lock and fcntl is not None:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        if lock:
            lock.close()


def _sync_one_task(client, taskid, task_name):
    """同步单个任务：漏洞（分页全量去重）+ 网站（queryjob）→ 先删旧再批量插入"""
    # 1. 漏洞：分页全量（web_task_vulns 含 300s 缓存，同步时绕过缓存）
    vulns = _fetch_vulns_no_cache(client, taskid)
    high_total = sum(1 for v in vulns if str(v.get('severity')) == '0')

    # 2. 网站：queryjob（单任务，忽略 length 一次返回）
    sites = []
    try:
        sites = client.web_sites(taskid=taskid)
    except Exception as e:
        logger.warning('[vscan-sync] 任务 %s 网站拉取失败: %s', taskid, e)
    # ⚠️ 2026-08-22：queryjob 对同一 URL 有多条记录（不同 jobid/批次）→ 按 URL 去重
    uniq_sites = {}
    for s in sites:
        u = s.get('url') or ''
        if u and u not in uniq_sites:
            uniq_sites[u] = s
    sites = list(uniq_sites.values())
    site_total = len(sites)

    # 3. 扫描时间：取第一个网站的结束时间
    scan_time = None
    for s in sites:
        t_str = s.get('end') or s.get('start')
        if t_str:
            try:
                naive = timezone.datetime.strptime(t_str, '%Y-%m-%d %H:%M:%S')
                scan_time = timezone.make_aware(naive) if timezone.is_naive(naive) else naive
                break
            except Exception:
                pass

    # 4. 先删该 taskid 旧数据（快照一致性），再批量插入
    VscanWebVuln.objects.filter(taskid=taskid).delete()
    VscanWebSite.objects.filter(taskid=taskid).delete()

    def _bulk(model, objs):
        try:
            model.objects.bulk_create(objs, batch_size=500, ignore_conflicts=True)
        except Exception:
            # 老版本 SQLite 不支持 ON CONFLICT（<3.24）→ 降级为非 ignore 顺序插入
            for o in objs:
                try:
                    o.save()
                except Exception:
                    pass

    if vulns:
        _bulk(VscanWebVuln, [
            VscanWebVuln(
                taskid=taskid, task_name=task_name, severity=int(v.get('severity') or 0),
                name=v.get('name') or '', url=v.get('url') or '',
                category=v.get('category') or '', param=v.get('param') or '',
                comment=v.get('comment') or '', testcase=v.get('testcase') or '',
                pluginid=int(v.get('pluginid') or 0), scan_time=scan_time,
            ) for v in vulns
        ])
    if sites:
        _bulk(VscanWebSite, [
            VscanWebSite(taskid=taskid, task_name=task_name, url=s.get('url') or '',
                         jobid=str(s.get('jobid') or ''), scan_time=scan_time)
            for s in sites
        ])

    # 5. 任务统计（site_total 用唯一网站数）
    try:
        raw_total = client.web_vulns(taskid, 0, length=1, start=0).get('total') or 0
    except Exception:
        raw_total = 0
    VscanWebTask.objects.update_or_create(
        taskid=taskid,
        defaults={
            'task_name': task_name, 'scan_time': scan_time,
            'site_total': site_total, 'vuln_total': raw_total,
            'high_total': high_total, 'dedup_total': len(vulns),
        },
    )
    logger.info('[vscan-sync] 任务 %s(%s): %d 漏洞 / %d 网站', taskid, task_name, len(vulns), site_total)


def _fetch_vulns_no_cache(client, taskid):
    """拉任务级漏洞（绕过 web_task_vulns 的缓存，强制全量）"""
    out = []
    seen = set()
    start = 0
    while True:
        res = client.web_vulns(taskid, 0, length=500, start=start)
        rows = res.get('data') or []
        raw = res.get('raw') or 0
        if not rows:
            break
        for r in rows:
            key = (str(r.get('severity')), str(r.get('name')), str(r.get('url')))
            if key in seen:
                continue
            seen.add(key)
            out.append(r)
        if raw < 500:
            break
        start += 500
    return out


def _cleanup_old():
    """删除 60 天前的数据（任务/网站/漏洞）"""
    try:
        cutoff = timezone.now() - timedelta(days=KEEP_DAYS)
        old_tasks = list(VscanWebTask.objects.filter(sync_time__lt=cutoff).values_list('taskid', flat=True))
        if old_tasks:
            VscanWebVuln.objects.filter(taskid__in=old_tasks).delete()
            VscanWebSite.objects.filter(taskid__in=old_tasks).delete()
            VscanWebTask.objects.filter(taskid__in=old_tasks).delete()
            logger.info('[vscan-sync] 清理 %d 个过期任务（>%d 天）', len(old_tasks), KEEP_DAYS)
        else:
            VscanWebVuln.objects.filter(sync_time__lt=cutoff).delete()
            VscanWebSite.objects.filter(sync_time__lt=cutoff).delete()
            VscanWebTask.objects.filter(sync_time__lt=cutoff).delete()
    except Exception as e:
        logger.warning('[vscan-sync] 清理失败: %s', e)
