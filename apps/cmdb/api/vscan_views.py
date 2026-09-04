# -*- coding: utf-8 -*-
"""
华为 VSCAN1506 漏洞扫描 API（2026-08-21）
数据源：vScan（192.168.100.2）实时透传（方案 A：vScan 报告更新 → eSight 刷新即最新）
接口：
  GET /vscan/stats/          大屏统计（任务数/漏洞总数/高危数/等级分布/TOP资产）
  GET /vscan/tasks/          扫描任务列表
  GET /vscan/vulns/          漏洞列表（分页 + 过滤：ip/name/severity/asset/os/port）
  GET /vscan/vulns/detail/   漏洞详情（pluginid）
"""
import json
import logging
import time

from django.db.models import Count, Q
from django.http import JsonResponse
from rest_framework.views import APIView
from rest_framework.authentication import SessionAuthentication

from apps.cmdb.services.vscan_client import get_client, get_report_client

logger = logging.getLogger('app')

# 进程内 TTL 缓存（无 redis 依赖）：避免每次打开页面都实时拉 vScan 上游（单次 ~17s）
# 2026-08-25：TTL 由 60s 放宽到 1 天（86400s）——vScan 扫描按周进行，1 天缓存足够；
# 需要即时刷新时 GET 加 ?refresh=1/true/yes 强制回源（手动刷新）。
_CACHE = {}
_CACHE_TTL = 86400


def _cache_get(key, loader, force=False):
    """命中且未过期直接返回；force=True 时忽略缓存强制回源（手动刷新场景）。
    loader 抛异常不缓存，交由调用方 try/except 处理。"""
    if not force:
        now = time.time()
        item = _CACHE.get(key)
        if item and now - item[0] < _CACHE_TTL:
            return item[1]
    val = loader()
    _CACHE[key] = (time.time(), val)
    return val

# vScan 风险等级：0=信息/1=低/2=中/3=高/4=严重
SEV_TEXT = {'0': '信息', '1': '低', '2': '中', '3': '高', '4': '严重'}
SEV_CLS = {'0': 'info', '1': 'low', '2': 'mid', '3': 'high', '4': 'crit'}

# WEB 漏洞风险等级（scanlogsystem 与 vullogsystem 相反！）：0=高/1=中/2=低/3=信息
SEV_TEXT_WEB = {'0': '高', '1': '中', '2': '低', '3': '信息'}
SEV_CLS_WEB = {'0': 'high', '1': 'mid', '2': 'low', '3': 'info'}


class CSRFExemptSessionAuthentication(SessionAuthentication):
    def enforce_csrf(self, request):
        return


def _ok(data=None, msg='信息获取成功'):
    if data is None:
        data = {}
    return JsonResponse({'code': 200, 'successcode': 20005, 'message': msg, 'data': data})


def _err(msg, code=400):
    return JsonResponse({'code': code, 'successcode': 40001, 'message': msg, 'data': None})


def _sev_out(v):
    s = str(v or '')
    return {'id': s, 'text': SEV_TEXT.get(s, s), 'cls': SEV_CLS.get(s, '')}


def _parse_detail(s):
    """vuln_list 的 detail 是 dict，同步时 json.dumps 入库；读取时还原。"""
    if not s:
        return {}
    try:
        return json.loads(s)
    except Exception:
        return {}


class VScanStatsView(APIView):
    """大屏统计（2026-08-26 v2：改查本地 DB VscanVuln，秒开；不再实时拉 vScan 8-20s）
    ⚠️ 请求路径零上游调用：漏洞聚合走 DB，任务概要来自同步 meta（sync_all 时顺带拉一次）。
    ?refresh=1/true/yes → 后台触发一次同步（不阻塞，返回当前 DB 数据）。
    """
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        if request.GET.get('refresh') in ('1', 'true', 'yes'):
            # 手动刷新：后台触发同步（非阻塞），随后仍返回当前 DB 数据
            try:
                from apps.cmdb.services.vscan_sys_sync import sync_trigger
                sync_trigger()
            except Exception:
                logger.warning('[vscan] stats refresh trigger failed')
        try:
            from apps.cmdb.models import VscanVuln
            from apps.cmdb.services.vscan_client import cache_get_meta
            total = VscanVuln.objects.count()
            sev_qs = VscanVuln.objects.values('severity').annotate(c=Count('id'))
            sev_dist = {str(s['severity']): s['c'] for s in sev_qs}
            high_cnt = sum(v for k, v in sev_dist.items() if k in ('3', '4'))
            assets_qs = VscanVuln.objects.values('ip', 'asset_name', 'os').annotate(
                c=Count('id'), high=Count('id', filter=Q(severity__in=[3, 4])))
            top_assets = sorted(
                [{'name': a['asset_name'] or a['ip'] or '未知', 'ip': a['ip'] or '',
                  'os': a['os'] or '', 'cnt': a['c'], 'high': a['high']} for a in assets_qs],
                key=lambda x: (-x['high'], -x['cnt']))[:10]
            recent = [{'name': v.name, 'ip': v.ip, 'asset': v.asset_name,
                       'severity': str(v.severity),
                       'sev_text': SEV_TEXT.get(str(v.severity), ''),
                       'port': v.port, 'time': v.time}
                      for v in VscanVuln.objects.order_by('-id')[:20]]
            # 任务概要来自同步 meta（同步时拉一次，避免读路径打上游）
            meta = cache_get_meta('vuln_sync') or {}
            return _ok({
                'task_total': meta.get('task_total', 0),
                'task_running': meta.get('task_running', 0),
                'task_finished': meta.get('task_finished', 0),
                'vuln_total': total,
                'high_cnt': high_cnt,
                'sev_dist': [{'severity': SEV_TEXT.get(k, k), 'cnt': v}
                             for k, v in sorted(sev_dist.items())],
                'top_assets': top_assets,
                'recent': recent,
            })
        except Exception as e:
            logger.exception('[vscan] stats DB error')
            return _err('数据库查询失败: {}'.format(e), 502)


class VScanTasksView(APIView):
    """扫描任务列表"""
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        try:
            tasks = get_client().task_list()
        except Exception as e:
            logger.exception('[vscan] tasks error')
            return _err('vScan 连接失败: {}'.format(e), 502)
        return _ok({'total': len(tasks), 'data': tasks})


class VScanVulnsView(APIView):
    """漏洞列表（分页，前端按 f 过滤）
    ⚠️ 2026-08-26 v2：改查本地 DB VscanVuln（秒开）；不再实时拉 vScan 上游。
    漏洞列表 + 资产视图共用本端点，两者一并受益。
    ?refresh=1/true/yes → 后台触发一次同步（不阻塞，返回当前 DB 数据）。
    """
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        if request.GET.get('refresh') in ('1', 'true', 'yes'):
            try:
                from apps.cmdb.services.vscan_sys_sync import sync_trigger
                sync_trigger()
            except Exception:
                logger.warning('[vscan] vulns refresh trigger failed')
        try:
            from apps.cmdb.models import VscanVuln
            length = min(int(request.GET.get('limit') or 500), 2000)
            start = max(int(request.GET.get('offset') or 0), 0)
            qs = VscanVuln.objects.all()
            total = qs.count()
            rows = qs.order_by('severity', 'name')[start:start + length]
            data = [{
                'asset_group': v.asset_group, 'asset_name': v.asset_name,
                'ip': v.ip, 'admin': v.admin, 'os': v.os,
                'severity': _sev_out(v.severity),
                'name': v.name, 'port': v.port, 'time': v.time,
                'rid': v.rid, 'detail': _parse_detail(v.detail),
            } for v in rows]
            return _ok({'total': total, 'data': data})
        except Exception as e:
            logger.exception('[vscan] vulns DB error')
            return _err('数据库查询失败: {}'.format(e), 502)


class VScanVulnDetailView(APIView):
    """漏洞详情（pluginid → 描述/解决方案/CVE）"""
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        pluginid = request.GET.get('pluginid')
        if not pluginid:
            return _err('缺少 pluginid')
        try:
            d = get_client().vuln_detail(pluginid)
        except Exception as e:
            logger.exception('[vscan] vuln detail error')
            return _err('vScan 连接失败: {}'.format(e), 502)
        if not d:
            return _err('漏洞详情获取失败')
        return _ok({
            'id': d.get('id'), 'name': d.get('name'), 'group': d.get('groupname'),
            'synopsis': d.get('synopsis'), 'description': d.get('description'),
            'solution': d.get('solution'), 'cves': d.get('cves'), 'bids': d.get('bids'),
            'cvss_vector': d.get('cvss_vector'), 'cnvd': d.get('cnvd'),
            'cncve': d.get('cncve'), 'cnnvd': d.get('cnnvd'),
            'severity': _sev_out(d.get('severity')),
        })


class VScanVulnSyncView(APIView):
    """系统漏洞数据同步：懒检测 / 触发同步 / 状态查询（镜像 VScanWebSyncView）
    GET ?action=check   → 懒检测（DB 是否有新鲜数据）
    GET ?action=trigger → 未同步则后台触发全量同步
    GET ?action=status  → 同步进度（building/done_tasks/total_tasks/msg/vuln_total/high_total）
    """
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        action = request.GET.get('action') or 'check'
        from apps.cmdb.services.vscan_sys_sync import check_new_report, sync_trigger, sync_status
        try:
            if action == 'trigger':
                return _ok(sync_trigger())
            if action == 'status':
                return _ok(sync_status())
            return _ok(check_new_report())
        except Exception as e:
            logger.exception('[vscan] vuln sync error')
            return _err('同步服务错误: {}'.format(e), 502)


# ═══════════ WEB 漏洞（scanlogsystem，report 账号）═══════════
def _sev_web(v):
    s = str(v if v is not None else '')
    return {'id': s, 'text': SEV_TEXT_WEB.get(s, s), 'cls': SEV_CLS_WEB.get(s, '')}


class VScanWebStatsView(APIView):
    """WEB 漏洞大屏统计：任务数 + 任务列表
    ⚠️ 不拉全量网站（queryjob 单请求 ~17s，串行 6 任务 100s+ 会超时）；网站总数由
    web/sites 接口返回（后端已并发优化 ~20s），大屏只展示任务维度。
    """
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        try:
            # ?refresh=1/true/yes 强制回源（手动刷新）；否则命中 1 天缓存
            _refresh = request.GET.get('refresh') in ('1', 'true', 'yes')
            tasks = _cache_get('vscan_web_tasks', lambda: get_report_client().web_tasks(), force=_refresh)
        except Exception as e:
            logger.exception('[vscan] web stats error')
            return _err('vScan 连接失败: {}'.format(e), 502)
        return _ok({
            'task_total': len(tasks),
            'tasks': [{'taskid': t['taskid'], 'name': t['name']} for t in tasks],
        })


class VScanWebSitesView(APIView):
    """WEB 网站列表（queryjob）→ 按任务过滤可选 taskid"""
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        taskid = request.GET.get('taskid')
        try:
            sites = get_report_client().web_sites(int(taskid) if taskid else None)
        except Exception as e:
            logger.exception('[vscan] web sites error')
            return _err('vScan 连接失败: {}'.format(e), 502)
        return _ok({'total': len(sites), 'data': sites})


class VScanWebVulnsView(APIView):
    """任务级漏洞列表（本地 DB 查询，秒开）
    ⚠️ 2026-08-22 v6：改查 VscanWebVuln 表（不再实时拉 vScan）
    sev_only='0' → 只查高危
    """
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        taskid = request.GET.get('taskid')
        if not taskid:
            return _err('缺少 taskid')
        sev_only = request.GET.get('sev_only')
        try:
            tid = int(taskid)
            # 支持前端分页（limit/offset），默认 2000、上限 5000，避免一次性拉全量压垮
            try:
                limit = min(int(request.GET.get('limit', 2000) or 2000), 5000)
                offset = max(int(request.GET.get('offset', 0) or 0), 0)
            except (TypeError, ValueError):
                limit, offset = 2000, 0
            # ?refresh=1/true/yes 强制回源（手动刷新）；否则命中 1 天缓存
            # 2026-08-25：按 (taskid, sev_only, limit, offset) 建键——新扫描产生新 taskid →
            # 自然命中新键，不会因同步写入而读到陈旧数据；同 taskid 重复同步可用 ?refresh=1 强刷。
            _refresh = request.GET.get('refresh') in ('1', 'true', 'yes')
            key = ('vscan_web_vulns', tid, sev_only, limit, offset)

            def _load():
                from apps.cmdb.models import VscanWebVuln
                qs = VscanWebVuln.objects.filter(taskid=tid)
                if sev_only:
                    qs = qs.filter(severity=0)
                total = qs.count()
                rows = qs.order_by('severity', 'name')[offset:offset + limit]
                data = [{
                    'severity': _sev_web(str(v.severity)),
                    'name': v.name, 'category': v.category,
                    'url': v.url, 'param': v.param, 'comment': v.comment,
                    'testcase': v.testcase, 'pluginid': str(v.pluginid),
                    'taskid': v.taskid,
                } for v in rows]
                return {'total': total, 'data': data, 'limit': limit, 'offset': offset}
            payload = _cache_get(key, _load, force=_refresh)
            return _ok(payload)
        except Exception as e:
            logger.exception('[vscan] web vulns DB error')
            return _err('数据库查询失败: {}'.format(e), 502)


class VScanWebVulnDetailView(APIView):
    """WEB 漏洞详情（scanplugins/detail）"""
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        pluginid = request.GET.get('pluginid')
        if not pluginid:
            return _err('缺少 pluginid')
        try:
            d = get_report_client().web_vuln_detail(pluginid)
        except Exception as e:
            logger.exception('[vscan] web vuln detail error')
            return _err('vScan 连接失败: {}'.format(e), 502)
        if not d:
            return _err('漏洞详情获取失败')
        return _ok({
            'id': d.get('id'), 'name': d.get('name'), 'group': d.get('groupname'),
            'descr': d.get('descr') or d.get('description'), 'solution': d.get('solution'),
            'severity': _sev_web(d.get('severity')),
            'url': d.get('url'), 'param': d.get('param'),
            'testcase': d.get('testcase'), 'comment': d.get('comment'),
        })


class VScanWebCardsView(APIView):
    """WEB 任务列表（本地 DB，秒开）：任务 desc + 网站数/漏洞数/高危数"""
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        try:
            from apps.cmdb.models import VscanWebTask
            tasks = VscanWebTask.objects.order_by('-taskid')[:50]
            cards = [{
                'taskid': t.taskid, 'name': t.task_name,
                'site_total': t.site_total, 'vuln_total': t.vuln_total,
                'high_total': t.high_total, 'dedup_total': t.dedup_total,
                'scan_time': t.scan_time.strftime('%Y-%m-%d %H:%M:%S') if t.scan_time else '',
            } for t in tasks]
            return _ok({'task_total': len(cards), 'cards': cards})
        except Exception as e:
            logger.exception('[vscan] web cards DB error')
            return _err('数据库查询失败: {}'.format(e), 502)


class VScanWebSyncView(APIView):
    """WEB 数据同步：懒检测 / 触发同步 / 状态查询
    GET ?action=check   → 懒检测（DB 最新 taskid vs vScan 第一条）
    GET ?action=trigger → 未同步则后台触发全量同步
    GET ?action=status  → 同步进度（building/done_tasks/total_tasks/current_task）
    """
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        action = request.GET.get('action') or 'check'
        from apps.cmdb.services.vscan_web_sync import check_new_report, sync_trigger, sync_status
        try:
            if action == 'trigger':
                return _ok(sync_trigger())
            if action == 'status':
                return _ok(sync_status())
            return _ok(check_new_report())
        except Exception as e:
            logger.exception('[vscan] web sync error')
            return _err('同步服务错误: {}'.format(e), 502)


class VScanWebCompareView(APIView):
    """WEB 报告对比（整改对比）：两个 taskid 的漏洞 diff
    GET ?a=taskidA&b=taskidB → {new:[本次有上次无], fixed:[上次有本次无], remain:[两次都有]}
    a=最新报告, b=上次报告
    """
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        a = request.GET.get('a')
        b = request.GET.get('b')
        if not a or not b:
            return _err('缺少 a/b taskid')
        try:
            from apps.cmdb.models import VscanWebVuln
            def _keys(taskid):
                qs = VscanWebVuln.objects.filter(taskid=int(taskid))
                return {(v.severity, v.name, v.url): v for v in qs}
            set_a = _keys(a)
            set_b = _keys(b)
            key_a = set(set_a.keys())
            key_b = set(set_b.keys())
            new_keys = key_a - key_b
            fixed_keys = key_b - key_a
            remain_keys = key_a & key_b
            def _out(keys, kv):
                return [{
                    'severity': _sev_web(str(kv[k].severity)), 'name': kv[k].name,
                    'url': kv[k].url, 'category': kv[k].category, 'param': kv[k].param,
                } for k in sorted(keys)]
            return _ok({
                'a_taskid': int(a), 'b_taskid': int(b),
                'new_total': len(new_keys), 'fixed_total': len(fixed_keys),
                'remain_total': len(remain_keys),
                'new': _out(new_keys, set_a), 'fixed': _out(fixed_keys, set_b),
                'remain': _out(remain_keys, set_a),
            })
        except Exception as e:
            logger.exception('[vscan] web compare error')
            return _err('对比失败: {}'.format(e), 502)


class VScanWebFullView(APIView):
    """WEB 全量去重漏洞：构建状态查询 / 触发构建 / 取结果
    GET 无参数 → 返回当前状态（building/done/数据摘要）
    前端轮询此接口：building=true 显示进度，done=true 拉取全部漏洞列表
    """
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        try:
            c = get_report_client()
            status = c.web_full_build()
            if status.get('done'):
                data = c.web_full_get()
                rows = []
                if data:
                    for v in data.get('data') or []:
                        rows.append({
                            'severity': _sev_web(v.get('severity')),
                            'name': v.get('name'), 'category': v.get('category'),
                            'param': v.get('param'), 'comment': v.get('comment'),
                            'testcase': v.get('testcase'), 'pluginid': v.get('pluginid'),
                            'taskid': v.get('taskid'),
                        })
                return _ok({
                    'building': False, 'done': True,
                    'task_total': status.get('task_total', 0),
                    'site_total': status.get('site_total', 0),
                    'vuln_total': status.get('vuln_total', 0),
                    'high_cnt': status.get('high_cnt', 0),
                    'data': rows,
                })
            return _ok(status)
        except Exception as e:
            logger.exception('[vscan] web full error')
            return _err('vScan 连接失败: {}'.format(e), 502)


class VScanWebHighView(APIView):
    """WEB 高危漏洞实时查询（等级 0 高）：并发拉各任务网站 → 仅查等级 0 → 去重
    数据量小，秒级返回。前端点任务卡片后展示高危列表。
    """
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        taskid = request.GET.get('taskid')
        try:
            res = get_report_client().web_high_vulns(int(taskid) if taskid else None)
        except Exception as e:
            logger.exception('[vscan] web high error')
            return _err('vScan 连接失败: {}'.format(e), 502)
        rows = [{
            'severity': _sev_web(v.get('severity')),
            'name': v.get('name'), 'category': v.get('category'),
            'url': v.get('url'), 'param': v.get('param'), 'comment': v.get('comment'),
            'testcase': v.get('testcase'), 'pluginid': v.get('pluginid'),
            'taskid': v.get('taskid'),
        } for v in res.get('data') or []]
        return _ok({'high_total': res.get('high_total', 0), 'data': rows})


class VScanVulnExportView(APIView):
    """系统漏洞 CSV 导出（本地 DB VscanVuln，秒开；复用前端 f 过滤：ip/name/severity/asset_name/port）
    导出当前筛选集——所见即所导（前端漏洞列表的过滤条件原样传入）。"""
    authentication_classes = [CSRFExemptSessionAuthentication]

    COLUMNS = [
        ('asset_group', '资产组'), ('asset_name', '资产名称'), ('ip', 'IP'),
        ('admin', '负责人'), ('os', '操作系统'), ('severity', '风险等级'),
        ('name', '漏洞名称'), ('port', '端口'), ('time', '发现时间'), ('rid', '漏洞ID'),
    ]

    def get(self, request):
        import csv
        from django.http import HttpResponse
        from apps.cmdb.models import VscanVuln
        qs = VscanVuln.objects.all()
        f_ip = request.GET.get('ip')
        f_name = request.GET.get('name')
        f_sev = request.GET.get('severity')
        f_asset = request.GET.get('asset_name')
        f_port = request.GET.get('port')
        if f_ip:
            qs = qs.filter(ip__icontains=f_ip)
        if f_name:
            qs = qs.filter(name__icontains=f_name)
        if f_sev:
            qs = qs.filter(severity=f_sev)
        if f_asset:
            qs = qs.filter(asset_name__icontains=f_asset)
        if f_port:
            qs = qs.filter(port__icontains=f_port)
        resp = HttpResponse(content_type='text/csv')
        resp['Content-Type'] = 'text/csv; charset=utf-8-sig'
        resp['Content-Disposition'] = 'attachment; filename="vscan_vulns.csv"'
        resp.write('\ufeff')
        writer = csv.writer(resp)
        writer.writerow([c[1] for c in self.COLUMNS])
        fields = [c[0] for c in self.COLUMNS]
        for v in qs.order_by('severity', 'name').iterator(chunk_size=2000):
            row = []
            for fld in fields:
                val = getattr(v, fld)
                if fld == 'severity':
                    val = SEV_TEXT.get(str(val), str(val))
                row.append('' if val is None else str(val))
            writer.writerow(row)
        return resp


class VScanWebVulnExportView(APIView):
    """WEB 漏洞 CSV 导出（本地 DB VscanWebVuln；taskid 必填，sev_only='0' 仅高危）"""
    authentication_classes = [CSRFExemptSessionAuthentication]

    COLUMNS = [
        ('severity', '风险等级'), ('name', '漏洞名称'), ('category', '分类'),
        ('url', '漏洞URL'), ('param', '问题参数'), ('comment', '备注'),
        ('testcase', '测试用例'), ('pluginid', 'ruleid'), ('taskid', '任务ID'),
    ]

    def get(self, request):
        import csv
        from django.http import HttpResponse
        from apps.cmdb.models import VscanWebVuln
        taskid = request.GET.get('taskid')
        if not taskid:
            return _err('缺少 taskid')
        try:
            tid = int(taskid)
        except ValueError:
            return _err('taskid 格式错误')
        qs = VscanWebVuln.objects.filter(taskid=tid)
        if request.GET.get('sev_only'):
            qs = qs.filter(severity=0)
        resp = HttpResponse(content_type='text/csv')
        resp['Content-Type'] = 'text/csv; charset=utf-8-sig'
        resp['Content-Disposition'] = 'attachment; filename="vscan_web_vulns_task%s.csv"' % tid
        resp.write('\ufeff')
        writer = csv.writer(resp)
        writer.writerow([c[1] for c in self.COLUMNS])
        fields = [c[0] for c in self.COLUMNS]
        for v in qs.order_by('severity', 'name').iterator(chunk_size=2000):
            row = []
            for fld in fields:
                val = getattr(v, fld)
                if fld == 'severity':
                    val = SEV_TEXT_WEB.get(str(val), str(val))
                row.append('' if val is None else str(val))
            writer.writerow(row)
        return resp
