# -*- coding: utf-8 -*-
"""
eSight 主机监控大屏 API
=======================
2026-08-14 新增：主机管理 → 主机监控大屏。

三数据源统一代理：
  1. 正式平台 control  —— 主机列表/分组/控制器（转发，不落库）
  2. 正式平台 cmdb     —— 主机详细字段/关联资源（转发，不落库）
  3. Zabbix           —— 实时曲线/当前告警/历史告警（直连 JSON-RPC）

前端统一走本模块 API，Zabbix 凭据不外泄。

⚠️ 正式平台地址：BK_URL 配置指向正式平台（192.168.99.24）时才可用；
   测试平台（192.168.99.31）没有真实主机数据。联调前先验证网络可达。
"""
import json
import logging
import os
import threading
import time

from django.http import JsonResponse
from rest_framework.views import APIView
from rest_framework.authentication import SessionAuthentication

from apps.cmdb.services.zabbix_api import get_zabbix_api

logger = logging.getLogger('app')


class CSRFExemptSessionAuthentication(SessionAuthentication):
    """关掉 CSRF（平台统一会话 Cookie 认证，无 CSRF token）"""

    def enforce_csrf(self, request):
        return


def _ok(data=None, msg='信息获取成功'):
    if data is None:
        data = {}
    return JsonResponse({'code': 200, 'successcode': 20005, 'message': msg, 'data': data})


def _err(msg):
    return JsonResponse({'code': 400, 'successcode': 40001, 'message': msg, 'data': None})


def _platform_base():
    """主机监控数据源正式平台 base。
    ⚠️ 不能读 BK_URL（那是 eSight 自己所在平台，测试环境是 99.31 没有真实主机数据）。
    用独立环境变量 HOST_MONITOR_PLATFORM_URL，默认正式平台 192.168.99.24。
    """
    return (os.environ.get('HOST_MONITOR_PLATFORM_URL') or 'https://192.168.99.24').rstrip('/')


def _prod_username():
    return os.environ.get('HOST_MONITOR_PLATFORM_USER') or '13537154433'


def _prod_password():
    return os.environ.get('HOST_MONITOR_PLATFORM_PASSWORD') or 'Lin2182693.'


# 正式平台服务账号 token 缓存（跨 worker 有 locmem 限制，但转发本身每次请求刷新过期即可；
# 这里只做进程内缓存 + 401 自动重登）
_prod_token = {'value': '', 'at': 0}
_prod_token_lock = threading.Lock()
_PROD_TOKEN_TTL = 3600 * 6  # 6h 内复用（平台 bk_token 有效期更长）


def _get_prod_token(force=False):
    """获取正式平台服务账号 bk_token（登录 API 返回在 JSON body）。
    返回 (token, err)"""
    global _prod_token
    now = time.time()
    if not force and _prod_token['value'] and now - _prod_token['at'] < _PROD_TOKEN_TTL:
        return _prod_token['value'], None
    import requests as _req
    try:
        r = _req.post(
            '{}/login/api/v3/login/'.format(_platform_base()),
            json={'username': _prod_username(), 'password': _prod_password(),
                  'c_url': '/o/control/'},
            timeout=15, verify=False,
        )
        body = r.json()
        token = (body.get('data') or {}).get('bk_token') or ''
        if not token:
            return '', '正式平台登录失败: {}'.format(body.get('message', body))
        with _prod_token_lock:
            _prod_token['value'] = token
            _prod_token['at'] = now
        return token, None
    except Exception as e:
        return '', '正式平台登录异常: {}'.format(e)


def _forward(request, app, platform_path):
    """转发到正式平台（带服务账号 bk_token）。401 时自动重登一次。"""
    import requests as _req
    url = '{}/o/{}/api/{}/v0_1/{}'.format(
        _platform_base(), app, app, platform_path)
    token, err = _get_prod_token()
    if err:
        return JsonResponse({'code': 50000, 'message': err, 'data': None})
    try:
        common = dict(params=request.GET, cookies={'bk_token': token}, timeout=25, verify=False)
        if request.method == 'POST':
            headers = {'Content-Type': request.content_type or 'application/json'}
            r = _req.post(url, data=request.body, headers=headers, **common)
        elif request.method == 'PUT':
            headers = {'Content-Type': request.content_type or 'application/json'}
            r = _req.put(url, data=request.body, headers=headers, **common)
        else:
            r = _req.get(url, **common)
        if r.status_code == 200:
            body = r.json()
            # 401 → 强制重登重试一次
            if body.get('code') == 401:
                token2, err2 = _get_prod_token(force=True)
                if not err2:
                    common['cookies'] = {'bk_token': token2}
                    r = _req.get(url, **common) if request.method == 'GET' else _req.request(
                        request.method, url, data=request.body,
                        headers={'Content-Type': request.content_type or 'application/json'},
                        **common)
                    if r.status_code == 200:
                        return JsonResponse(r.json())
            return JsonResponse(body)
        return JsonResponse({'code': 50000, 'message': '正式平台转发失败 HTTP {}'.format(r.status_code), 'data': None})
    except Exception as e:
        logger.warning('[host_monitor] %s forward error: %s', platform_path, e)
        return JsonResponse({'code': 50000, 'message': '正式平台转发失败: {}'.format(e), 'data': None})


# ───────────────── 转发层（control / cmdb）─────────────────────────
class HostMonitorConfigView(APIView):
    """GET /host-monitor/config/ → 大屏前端配置
    ⚠️ 2026-08-17：抽屉弹窗 CMDB 地址可配置：
      - 测试环境默认指向正式平台（192.168.99.24，跨域需正式平台 cookie）
      - 正式部署时配 HOST_MONITOR_CMDB_BASE=/o/cmdb（同域）→ iframe 无跨域问题
    """
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        cmdb_base = (os.environ.get('HOST_MONITOR_CMDB_BASE') or '').rstrip('/')
        if not cmdb_base:
            # 未配置 → 指向数据源正式平台（测试环境默认行为）
            cmdb_base = _platform_base() + '/o/cmdb'
        return _ok({'cmdb_base': cmdb_base, 'platform_base': _platform_base()})


class HostListProxyView(APIView):
    """GET /host-monitor/host-list/ → control agent-admin/"""
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        return _forward(request, 'control', 'agent-admin/')

    def post(self, request):
        return _forward(request, 'control', 'agent-admin/')


class HostGroupsProxyView(APIView):
    """GET /host-monitor/host-groups/ → control host-group/"""
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        return _forward(request, 'control', 'host-group/')


class ControllerListProxyView(APIView):
    """GET /host-monitor/controller-list/ → control controller/"""
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        return _forward(request, 'control', 'controller/')


class HostDetailProxyView(APIView):
    """GET /host-monitor/host-detail/?model_code=&unique= → cmdb repo-inst-info/"""
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        model_code = request.GET.get('model_code', 'VIRTUAL_SERVER')
        unique = request.GET.get('unique', '')
        if not unique:
            return _err('参数错误: unique 必填')
        import requests as _req
        url = '{}/o/cmdb//api/cmdb/v0_1/repo-inst-info/?model_code={}&unique={}'.format(
            _platform_base(), model_code, unique)
        token, err = _get_prod_token()
        if err:
            return JsonResponse({'code': 50000, 'message': err, 'data': None})
        try:
            r = _req.get(url, cookies={'bk_token': token}, timeout=25, verify=False)
            return JsonResponse(r.json())
        except Exception as e:
            return JsonResponse({'code': 50000, 'message': 'cmdb 详情转发失败: {}'.format(e), 'data': None})


class HostRelationsProxyView(APIView):
    """GET /host-monitor/host-relations/?model_code=&unique= → cmdb get-res-relation/"""
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        model_code = request.GET.get('model_code', 'VIRTUAL_SERVER')
        unique = request.GET.get('unique', '')
        if not unique:
            return _err('参数错误: unique 必填')
        import requests as _req
        url = '{}/o/cmdb//api/cmdb/v0_1/get-res-relation/?model_code={}&unique={}'.format(
            _platform_base(), model_code, unique)
        token, err = _get_prod_token()
        if err:
            return JsonResponse({'code': 50000, 'message': err, 'data': None})
        try:
            r = _req.get(url, cookies={'bk_token': token}, timeout=25, verify=False)
            return JsonResponse(r.json())
        except Exception as e:
            return JsonResponse({'code': 50000, 'message': 'cmdb 关联转发失败: {}'.format(e), 'data': None})


# ───────────────── Zabbix 代理层 ──────────────────────────────────
# 常用指标 key → (item 描述, history 类型)。value_type: 0=float 3=uint
METRIC_KEYS = {
    'cpu_util': 'system.cpu.util',
    'cpu_load1': 'system.cpu.load[all,avg1]',
    'cpu_load5': 'system.cpu.load[all,avg5]',
    'cpu_load15': 'system.cpu.load[all,avg15]',
    'cpu_num': 'system.cpu.num',
    'mem_util': 'vm.memory.utilization',  # ⚠️ 2026-08-14 实测：实际 key 是 utilization 不是 util
    'mem_total': 'vm.memory.size[total]',
    'mem_available': 'vm.memory.size[available]',
    'disk_util': 'vfs.fs.used[,pfree]',
    'net_in': 'net.if.in',
    'net_out': 'net.if.out',
    'proc_num': 'proc.num',
    'agent_ping': 'agent.ping',
}

HISTORY_TYPE_FLOAT = 0   # float
HISTORY_TYPE_UINT = 3    # unsigned int


def _resolve_host(za, host_ip):
    """按 IP 查 Zabbix 主机，返回 hostid 或 None"""
    hosts = za.host_get(host_ip=host_ip)
    if hosts and len(hosts) > 0:
        return hosts[0]
    return None


def _find_items(za, host_id, key_list):
    """在一个请求里按前缀匹配多个 key。返回 {metric: itemdict}"""
    result = {}
    items = za.item_get(host_id, key_search=None, limit=500)
    if not items:
        return result
    for metric, key in key_list:
        for it in items:
            it_key = (it.get('key_') or '').lower()
            # 前缀匹配：system.cpu.util 精确；net.if.in 匹配 net.if.in["ens192"]；vm.memory.size[total] 精确
            base = key.rstrip(']').lower()
            if it_key == key.lower() or it_key.startswith(base + '[') or it_key.startswith(key.lower()):
                result.setdefault(metric, it)
                break
    return result


class ZabbixMetricsView(APIView):
    """POST /host-monitor/zabbix/metrics/ body: {host_ip, metrics:[...], range_sec:3600, history_type?}
    返回 {metric: {last_value, unit, points:[[clock, value], ...]}}
    """
    authentication_classes = [CSRFExemptSessionAuthentication]

    def post(self, request):
        try:
            data = json.loads(request.body)
        except Exception:
            return _err('参数错误')
        host_ip = data.get('host_ip', '')
        metrics = data.get('metrics') or ['cpu_util', 'mem_util']
        range_sec = int(data.get('range_sec') or 3600)
        if not host_ip:
            return _err('参数错误: host_ip 必填')

        za = get_zabbix_api()
        host = _resolve_host(za, host_ip)
        if not host:
            return _err('Zabbix 中未找到主机 {}（可能未接入监控）'.format(host_ip))
        host_id = host['hostid']

        # 解析 key 列表（支持 'cpu_util' 或原始 key）
        key_list = []
        for m in metrics:
            if m in METRIC_KEYS:
                key_list.append((m, METRIC_KEYS[m]))
            else:
                key_list.append((m, m))
        items = _find_items(za, host_id, key_list)
        if not items:
            return _err('主机 {} 未找到监控项'.format(host_ip))

        time_till = int(time.time())
        time_from = time_till - range_sec
        result = {}
        for metric, item in items.items():
            item_id = item['itemid']
            units = item.get('units') or ''
            last_value = item.get('lastvalue')
            # history 类型：value_type 0/1→float, 3→uint
            vt = str(item.get('value_type', '0'))
            htype = HISTORY_TYPE_UINT if vt == '3' else HISTORY_TYPE_FLOAT
            rows = za.history_get([item_id], time_from, time_till, limit=1500, history=htype) or []
            result[metric] = {
                'itemid': item_id,
                'name': item.get('name'),
                'key': item.get('key_'),
                'units': units,
                'last_value': last_value,
                'points': [[r['clock'], r['value']] for r in rows],
            }
        return _ok(result)


class ZabbixRealtimeView(APIView):
    """GET /host-monitor/zabbix/realtime/?ips=10.0.0.1,10.0.0.2&metrics=cpu_util,mem_util
    批量取多台主机最近值（列表实时列 / TOP10 用）。返回 {ip: {metric: last_value, ...}}
    """
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        ips = [i.strip() for i in (request.GET.get('ips') or '').split(',') if i.strip()]
        metrics = [m.strip() for m in (request.GET.get('metrics') or 'cpu_util,mem_util').split(',') if m.strip()]
        if not ips:
            return _err('参数错误: ips 必填')
        za = get_zabbix_api()
        # ⚠️ 2026-08-14 性能修复 v2：每个 metric 一次 item.get（hostids 数组 + 单 key search），
        #    15 台从 15 次请求降到 2 次（实测单字符串 search 有效，search 数组 0 结果）
        all_hosts = za.host_get(limit=500) or []
        host_by_ip = {}
        for h in all_hosts:
            host_by_ip.setdefault(h.get('host'), h)
        host_id_to_ip = {}
        for ip in ips:
            h = host_by_ip.get(ip)
            if h:
                host_id_to_ip[h['hostid']] = ip
        host_ids = list(host_id_to_ip.keys())
        out = {ip: {'online': False, 'values': {}} for ip in ips}
        if host_ids:
            for m in metrics:
                key = METRIC_KEYS.get(m, m)
                try:
                    items = za.item_get(host_ids, key_search=key, limit=500) or []
                except Exception as e:
                    logger.warning('[host_monitor] item_get %s error: %s', key, e)
                    items = []
                for it in items:
                    ip = host_id_to_ip.get(it.get('hostid'))
                    if ip and ip in out:
                        out[ip]['online'] = True
                        out[ip]['values'][m] = it.get('lastvalue')
        return _ok(out)


class ZabbixHostStatusView(APIView):
    """GET /host-monitor/zabbix/host-status/?ips=... → {ip: online/bool}"""
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        ips = [i.strip() for i in (request.GET.get('ips') or '').split(',') if i.strip()]
        za = get_zabbix_api()
        all_hosts = za.host_get(limit=500) or []
        host_by_ip = {h.get('host'): h for h in all_hosts}
        host_ids = []
        for ip in ips:
            h = host_by_ip.get(ip)
            if h:
                host_ids.append(h['hostid'])
        items = []
        if host_ids:
            items = za.item_get(host_ids, key_search='agent.ping', limit=500) or []
        ping_by_host = {it.get('hostid'): it.get('lastvalue') for it in items}
        out = {}
        for ip in ips:
            h = host_by_ip.get(ip)
            if not h:
                out[ip] = False
                continue
            out[ip] = str(ping_by_host.get(h['hostid'], '0')) == '1'
        return _ok(out)


class ZabbixAlarmsView(APIView):
    """GET /host-monitor/zabbix/alarms/?type=current|history&host_ip=&limit=
    当前告警：trigger.get(value=1) 未解决
    历史告警：event.get(value=0) 已恢复
    """
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        alarm_type = request.GET.get('type', 'current')
        host_ip = request.GET.get('host_ip', '')
        limit = int(request.GET.get('limit') or 200)
        za = get_zabbix_api()

        host_ids = None
        if host_ip:
            host = _resolve_host(za, host_ip)
            if not host:
                return _ok([])
            host_ids = host['hostid']

        if alarm_type == 'current':
            triggers = za.trigger_get(only_problems=True, host_ids=host_ids, limit=limit) or []
            out = []
            for t in triggers:
                hosts = t.get('hosts') or []
                out.append({
                    'triggerid': t.get('triggerid'),
                    'description': t.get('description'),
                    'priority': t.get('priority'),
                    'value': t.get('value'),
                    'lastchange': t.get('lastchange'),
                    'host': hosts[0].get('host') if hosts else '',
                })
            return _ok(out)
        else:
            events = za.event_get(source=3, value=0, host_ids=host_ids,
                                  time_from=int(time.time()) - 7 * 86400,
                                  time_till=int(time.time()), limit=limit) or []
            return _ok(events)


class ZabbixPingView(APIView):
    """GET /host-monitor/zabbix/ping/ → Zabbix API 连通性（联调用）"""
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        za = get_zabbix_api()
        ver = za.api_version()
        if ver:
            return _ok({'version': ver, 'url': za.url, 'user': za.user})
        return _err('Zabbix API 不可达')
