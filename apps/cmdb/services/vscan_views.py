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
import logging

from django.http import JsonResponse
from rest_framework.views import APIView
from rest_framework.authentication import SessionAuthentication

from apps.cmdb.services.vscan_client import get_client

logger = logging.getLogger('app')

# vScan 风险等级：0=信息/1=低/2=中/3=高/4=严重
SEV_TEXT = {'0': '信息', '1': '低', '2': '中', '3': '高', '4': '严重'}
SEV_CLS = {'0': 'info', '1': 'low', '2': 'mid', '3': 'high', '4': 'crit'}


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


class VScanStatsView(APIView):
    """大屏统计"""
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        try:
            st = get_client().stats()
        except Exception as e:
            logger.exception('[vscan] stats error')
            return _err('vScan 连接失败: {}'.format(e), 502)
        sev_dist = [{'severity': SEV_TEXT.get(k, k), 'cnt': v}
                    for k, v in sorted(st['sev_dist'].items())]
        top_assets = [{'name': a['name'], 'ip': a['ip'], 'os': a['os'],
                       'cnt': a['cnt'], 'high': a['high']} for a in st['top_assets']]
        recent = [{'name': v['name'], 'ip': v['ip'], 'asset': v['asset_name'],
                   'severity': v['severity'], 'sev_text': SEV_TEXT.get(str(v.get('severity')), ''),
                   'port': v['port'], 'time': v['time']} for v in st['recent']]
        return _ok({
            'task_total': st['task_total'],
            'task_running': st['task_running'],
            'task_finished': st['task_finished'],
            'vuln_total': st['vuln_total'],
            'high_cnt': st['high_cnt'],
            'sev_dist': sev_dist,
            'top_assets': top_assets,
            'recent': recent,
        })


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
    """漏洞列表（分页 + 过滤）"""
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        length = min(int(request.GET.get('limit') or 50), 500)
        start = int(request.GET.get('offset') or 0)
        # 过滤条件（透传给 vScan JSON）
        f = {}
        for k in ('assetgroup_name', 'asset_name', 'ip', 'adminuser_name', 'os', 'severity', 'name', 'port'):
            v = request.GET.get(k)
            if v:
                f[k] = v
        # 快捷过滤映射
        sev = request.GET.get('severity')
        if sev:
            _m = {'high': ['3', '4'], 'mid': ['2'], 'low': ['1'], 'info': ['0']}
            if sev.lower() in _m:
                f['severity'] = ','.join(_m[sev.lower()])
            else:
                f['severity'] = sev
        try:
            res = get_client().vuln_list(f, length=length, start=start)
        except Exception as e:
            logger.exception('[vscan] vulns error')
            return _err('vScan 连接失败: {}'.format(e), 502)
        rows = []
        for v in res['data']:
            rows.append({
                'asset_group': v['asset_group'], 'asset_name': v['asset_name'],
                'ip': v['ip'], 'admin': v['admin'], 'os': v['os'],
                'severity': _sev_out(v['severity']),
                'name': v['name'], 'port': v['port'], 'time': v['time'],
                'rid': v['rid'],
            })
        return _ok({'total': res['total'], 'data': rows})


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
