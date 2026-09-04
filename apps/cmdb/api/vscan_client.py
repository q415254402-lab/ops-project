# -*- coding: utf-8 -*-
"""
华为 VSCAN1506 漏洞扫描器客户端（2026-08-21）
数据源：华为 vScan（https://192.168.100.2，账号 operator/Operator@123）

对接要点（2026-08-21 逆向验证）：
  1. 登录免验证码：POST /login/，参数 username/password/csrf_token（csrf 从首页表单取），
     code 字段留空即可；必须带 header `X-Requested-With: XMLHttpRequest` + Referer，
     否则返回 HTML 登录页（伪装成"登录失败"）。
  2. 会话保持：登录成功 Set-Cookie adminid/adminname/admintype/random/tb（Max-Age=1800），
     requests.Session 自动携带；过期后重新登录。
  3. DataTables 接口必须 GET + 页面级 Referer + DataTables 参数
     (sEcho/iDisplayStart/iDisplayLength/sSortDir_0/...) + sSearch_0=过滤条件&bRegex_0=true；
     用 sSearch 全局参数会返回 HTML 登录页。
  4. 核心接口：
     - GET /taskmgr/tasklist/query/               任务列表
     - GET /statistic/vullogsystem/queryplugin/   漏洞明细（sSearch_0=JSON 过滤）
     - POST /hyberchannel/plugins/detail/         漏洞详情 {pluginid}
     - POST /statistic/vullogsystem/export/       导出 EXCEL
     - GET  /hyberchannel/assetmgr/queryjob/      资产任务
"""
import json
import logging
import threading
import time

import requests

logger = logging.getLogger('app')

# vScan 配置（环境变量可覆盖）
VSCAN_HOST = 'https://192.168.100.2'
VSCAN_USERNAME = 'operator'
VSCAN_PASSWORD = 'Operator@123'
VSCAN_TIMEOUT = 20


class VScanClient(object):
    """vScan 登录 + Cookie 会话 + 接口封装（带自动续期与并发锁）"""

    def __init__(self, host=VSCAN_HOST, username=VSCAN_USERNAME, password=VSCAN_PASSWORD):
        self.host = host.rstrip('/')
        self.username = username
        self.password = password
        self._session = None
        self._csrf = ''
        self._lock = threading.Lock()

    # ─────────── 会话管理 ───────────
    def _ensure_session(self):
        if self._session is not None:
            return self._session
        with self._lock:
            if self._session is not None:
                return self._session
            self._login()
            return self._session

    def _login(self):
        """登录 vScan（免验证码，code 留空）"""
        s = requests.Session()
        s.verify = False
        h0 = {'Referer': self.host + '/', 'X-Requested-With': 'XMLHttpRequest'}
        r = s.get(self.host + '/', headers=h0, timeout=VSCAN_TIMEOUT)
        import re
        m = re.search(r'name="csrf_token" value="([a-f0-9]+)"', r.text)
        csrf = m.group(1) if m else ''
        r2 = s.post(self.host + '/login/', headers=h0,
                    data={'username': self.username, 'password': self.password,
                          'code': '', 'csrf_token': csrf},
                    timeout=VSCAN_TIMEOUT)
        try:
            j = r2.json()
        except Exception:
            j = {}
        if not j.get('success'):
            raise RuntimeError('vScan 登录失败: {}'.format(j.get('msg') or r2.text[:120]))
        self._session = s
        self._csrf = csrf
        logger.info('[vscan] 登录成功 username=%s', self.username)

    def _get(self, path, referer, params=None, retry=True):
        """GET 带页面级 Referer + DataTables 参数；会话失效自动重登一次"""
        s = self._ensure_session()
        headers = {'Referer': referer, 'X-Requested-With': 'XMLHttpRequest'}
        try:
            r = s.get(self.host + path, headers=headers, params=params or {}, timeout=VSCAN_TIMEOUT)
        except requests.RequestException as e:
            logger.warning('[vscan] GET %s 网络错误: %s', path, e)
            if retry:
                self._reset_and_relogin()
                return self._get(path, referer, params, retry=False)
            raise
        # 会话失效（返回登录页 HTML）→ 重登一次
        if r.status_code == 200 and 'text/html' in (r.headers.get('content-type') or '') and 'username' in r.text[:2000]:
            if retry:
                logger.info('[vscan] 会话失效，重新登录后重试 %s', path)
                self._reset_and_relogin()
                return self._get(path, referer, params, retry=False)
        return r

    def _reset_and_relogin(self):
        with self._lock:
            self._session = None
            self._login()

    # ─────────── DataTables 参数 ───────────
    @staticmethod
    def _dt_params(bregex, length=100, start=0, sort_col=1, sort_dir='desc'):
        """构造 DataTables 服务端参数（sSearch_0=过滤条件&bRegex_0=true）"""
        return {
            'sEcho': '1', 'iDisplayStart': str(start), 'iDisplayLength': str(length),
            'iSortCol_0': str(sort_col), 'sSortDir_0': sort_dir, 'iSortingCols': '1',
            'sColumns': '',
            'sSearch_0': bregex, 'bRegex_0': 'true',
        }

    # ─────────── 业务接口 ───────────
    def task_list(self):
        """任务列表 → [{taskid,name,run_type,start,end,cost,progress,status,vul_cnt,type,...}]"""
        r = self._get('/taskmgr/tasklist/query/',
                      self.host + '/taskmgr/tasklist/',
                      self._dt_params('', length=200))
        try:
            j = r.json()
        except Exception:
            return []
        out = []
        for row in j.get('aaData') or []:
            out.append({
                'taskid': row[0], 'name': row[1], 'run_type': row[2],
                'start': row[3] or '', 'end': row[4] or '', 'cost': row[5] or '',
                'progress': row[6] or '', 'status': row[7], 'vul_cnt': row[8],
                'sort': row[9], 'task_type': row[10], 'owner': row[13] if len(row) > 13 else '',
            })
        return out

    def vuln_list(self, filters=None, length=100, start=0):
        """漏洞明细 → {total, data:[{asset_group,asset_name,ip,admin,os,severity,name,port,time,rid,detail}]}
        filters: {'assetgroup_name','asset_name','ip','adminuser_name','os','severity','name','port','from','to'}
        空过滤用 {"bRegex":"all"}
        """
        cond = filters or {}
        if not any(cond.values()):
            bregex = json.dumps({'bRegex': 'all'}, ensure_ascii=False)
        else:
            bregex = json.dumps(cond, ensure_ascii=False)
        r = self._get('/statistic/vullogsystem/queryplugin/',
                      self.host + '/statistic/vullogsystem/',
                      self._dt_params(bregex, length=length, start=start))
        try:
            j = r.json()
        except Exception:
            return {'total': 0, 'data': []}
        total = j.get('iTotalRecords') or 0
        rows = []
        for row in j.get('aaData') or []:
            det = row[10] if len(row) > 10 and isinstance(row[10], dict) else {}
            rows.append({
                'asset_group': row[0], 'asset_name': row[1], 'ip': row[2],
                'admin': row[3], 'os': row[4], 'severity': row[5],
                'name': row[6], 'port': row[7], 'time': row[8],
                'rid': row[9], 'detail': det,
            })
        return {'total': total, 'data': rows}

    def vuln_detail(self, pluginid):
        """漏洞详情（描述/解决方案/CVE 等）"""
        s = self._ensure_session()
        headers = {'Referer': self.host + '/statistic/vullogsystem/', 'X-Requested-With': 'XMLHttpRequest'}
        try:
            r = s.post(self.host + '/hyberchannel/plugins/detail/',
                       headers=headers, data={'pluginid': pluginid}, timeout=VSCAN_TIMEOUT)
            return r.json() if r.status_code == 200 else {}
        except Exception as e:
            logger.warning('[vscan] vuln_detail %s error: %s', pluginid, e)
            return {}

    def asset_list(self, length=200):
        """资产任务列表（含漏洞统计）→ 资产聚合用"""
        r = self._get('/hyberchannel/assetmgr/queryjob/',
                      self.host + '/hyberchannel/assetmgr/',
                      self._dt_params(json.dumps({'bRegex': 'all'}, ensure_ascii=False), length=length))
        try:
            j = r.json()
        except Exception:
            return []
        out = []
        for row in j.get('aaData') or []:
            out.append(row)
        return out

    def stats(self):
        """大屏统计：任务数 / 漏洞总数 / 等级分布 / TOP 资产 / 任务状态分布
        漏洞全量拉取（vScan 单页上限 500，分批拿）——数据量可控（773 条实测）
        """
        # 任务
        tasks = self.task_list()
        # 漏洞全量
        all_vulns = []
        total = None
        start = 0
        page = 500
        while True:
            res = self.vuln_list(None, length=page, start=start)
            if total is None:
                total = res.get('total') or 0
            all_vulns.extend(res.get('data') or [])
            if len(all_vulns) >= total or not res.get('data'):
                break
            start += page
        # 统计
        sev_dist = {'0': 0, '1': 0, '2': 0, '3': 0, '4': 0}
        high_cnt = 0
        assets = {}
        for v in all_vulns:
            s = str(v.get('severity', ''))
            sev_dist[s] = sev_dist.get(s, 0) + 1
            if s in ('3', '4'):
                high_cnt += 1
            key = v.get('ip') or v.get('asset_name') or '未知'
            a = assets.setdefault(key, {'name': v.get('asset_name') or key, 'ip': v.get('ip') or '',
                                        'os': v.get('os') or '', 'cnt': 0, 'high': 0})
            a['cnt'] += 1
            if s in ('3', '4'):
                a['high'] += 1
        top_assets = sorted(assets.values(), key=lambda x: -x['high'])[:10]
        # 任务状态: status 3=完成?（实测 3 为完成、6 为进行中、0 为排队，结合 vul_cnt 判断）
        running = sum(1 for t in tasks if t.get('status') in (1, 2, 6))
        finished = sum(1 for t in tasks if t.get('status') in (3, 4))
        return {
            'task_total': len(tasks),
            'task_running': running,
            'task_finished': finished,
            'vuln_total': total or len(all_vulns),
            'high_cnt': high_cnt,
            'sev_dist': sev_dist,
            'top_assets': top_assets,
            'recent': all_vulns[:20],
        }


# 模块级单例（线程安全）
_client = None
_client_lock = threading.Lock()


def get_client():
    global _client
    if _client is None:
        with _client_lock:
            if _client is None:
                _client = VScanClient()
    return _client
