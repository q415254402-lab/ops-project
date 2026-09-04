# -*- coding: utf-8 -*-
"""
华为 VSCAN1506 漏洞扫描器客户端（2026-08-21 v3：多 worker 会话共享 - 文件锁版）
数据源：华为 vScan（https://192.168.100.2，账号 operator/Operator@123）

v3 关键改动（2026-08-21）：
  ⚠️ vScan 同一账号并发登录会互相踢掉会话 → uwsgi 多 worker 各自持独立 session 时
     交替出现"会话失效返回 HTML"（实测 SEQ 0,773,0,0,0 极不稳定）。
     v2 用 Django cache 失败（esight 无 Redis，CACHES=locmem 进程内不共享）。
     v3 方案：会话 cookie 持久化到共享文件（容器内多 worker 同一文件系统）
     + 跨进程文件锁（fcntl）防并发登录互踢。每个 worker 仍保留进程内内存缓存减少 IO。

对接要点（2026-08-21 逆向验证）：
  1. 登录免验证码：POST /login/，参数 username/password/csrf_token（csrf 从首页表单取），
     code 字段留空即可；必须带 header `X-Requested-With: XMLHttpRequest` + Referer，
     否则返回 HTML 登录页（伪装成"登录失败"）。
  2. 会话保持：登录成功 Set-Cookie adminid/adminname/admintype/random/tb（Max-Age=1800）。
  3. DataTables 接口必须 GET + 页面级 Referer + DataTables 参数：
     - 任务列表 query：全局 sSearch（不能带 bRegex=true，会被拒）
     - 漏洞列表 queryplugin：sSearch_0=JSON&bRegex_0=true
  4. 每次查询前必须先 GET 功能页面（Referer 用首页 /），否则返回 HTML。
"""
import json
import logging
import os
import re
import threading
import time
import hashlib

import requests

try:
    import fcntl  # Linux
except ImportError:
    fcntl = None

logger = logging.getLogger('app')

# vScan 配置（环境变量可覆盖）
VSCAN_HOST = os.environ.get('VSCAN_HOST', 'https://192.168.100.2')
VSCAN_USERNAME = os.environ.get('VSCAN_USERNAME', 'operator')
VSCAN_PASSWORD = os.environ.get('VSCAN_PASSWORD', 'Operator@123')
VSCAN_TIMEOUT = int(os.environ.get('VSCAN_TIMEOUT', '60'))

# report 账号（2026-08-21：WEB 漏洞在 scanlogsystem，需独立账号避免与 operator 互踢）
VSCAN_REPORT_USERNAME = os.environ.get('VSCAN_REPORT_USERNAME', 'report')
VSCAN_REPORT_PASSWORD = os.environ.get('VSCAN_REPORT_PASSWORD', 'Report@123')

# 构建/同步锁超时（秒）：超过此时间仍 building 视为失效，调用方应重新触发。
# 防 uwsgi restart 在构建/同步中途杀线程导致 meta 永久 building=true 卡死。
BUILDING_TTL = int(os.environ.get('VSCAN_BUILDING_TTL', '600'))


def _is_building(meta):
    """meta 处于构建中且未超时返回 True；超时视为失效，调用方应重新触发。"""
    if not meta or not meta.get('building'):
        return False
    return (time.time() - meta.get('ts', 0)) < BUILDING_TTL


def _sync_building():
    """同步进行中（防并发登录 report 账号互踢）。懒导入避免循环依赖。"""
    try:
        from apps.cmdb.services.vscan_web_sync import SYNC_META_KEY
        return _is_building(cache_get_meta(SYNC_META_KEY))
    except Exception:
        return False


# 会话文件（容器内多 worker 共享文件系统；路径在 esight code 目录，重启不丢）
_SESSION_FILE = os.environ.get(
    'VSCAN_SESSION_FILE',
    '/opt/opsany/paas-agent/apps/projects/esight/code/esight/vscan_session.json',
)
_SESSION_FILE_REPORT = os.environ.get(
    'VSCAN_SESSION_FILE_REPORT',
    '/opt/opsany/paas-agent/apps/projects/esight/code/esight/vscan_session_report.json',
)
_SESSION_TTL = 1500  # 25 分钟（vScan cookie Max-Age=1800 前重登）

# ─────────── 文件缓存工具（多 worker 共享，fcntl 锁）───────────
# 2026-08-21 优化：stats 全量计算慢（~8s）、WEB 全量去重更慢（分钟级），
# 用文件缓存让二次请求秒开；多 worker 同一文件系统 + 文件锁防并发写冲突。
_CACHE_DIR = os.environ.get(
    'VSCAN_CACHE_DIR',
    '/opt/opsany/paas-agent/apps/projects/esight/code/esight/vscan_cache',
)


def _cache_path(key):
    h = hashlib.md5(key.encode('utf-8')).hexdigest()
    return os.path.join(_CACHE_DIR, h + '.json')


def cache_get(key, ttl):
    """读缓存：未过期返回 (True, data)，否则 (False, None)"""
    try:
        p = _cache_path(key)
        if not os.path.exists(p):
            return False, None
        with open(p) as f:
            d = json.load(f)
        if time.time() - d.get('ts', 0) > ttl:
            return False, None
        return True, d.get('data')
    except Exception:
        return False, None


def cache_set(key, data):
    """写缓存（原子替换，避免并发读到半截文件）"""
    try:
        os.makedirs(_CACHE_DIR, exist_ok=True)
        p = _cache_path(key)
        tmp = p + '.tmp'
        with open(tmp, 'w') as f:
            json.dump({'ts': time.time(), 'data': data}, f)
        os.replace(tmp, p)
    except Exception as e:
        logger.warning('[vscan] 缓存写失败 %s: %s', key, e)


def cache_lock(key):
    """跨进程写锁（防并发构建/计算重复触发）"""
    p = _cache_path(key) + '.lock'
    try:
        os.makedirs(_CACHE_DIR, exist_ok=True)
        f = open(p, 'a+')
        if fcntl is not None:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        return f
    except Exception:
        return None


def cache_get_meta(key):
    """读缓存元信息（用于构建状态查询：building/ts/err）"""
    try:
        p = _cache_path(key) + '.meta'
        if not os.path.exists(p):
            return None
        with open(p) as f:
            return json.load(f)
    except Exception:
        return None


def cache_set_meta(key, meta):
    try:
        os.makedirs(_CACHE_DIR, exist_ok=True)
        p = _cache_path(key) + '.meta'
        tmp = p + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(meta, f)
        os.replace(tmp, p)
    except Exception:
        pass



class VScanClient(object):
    """vScan 登录 + Cookie 会话 + 接口封装（多 worker 文件锁共享会话）
    2026-08-21：支持多账号实例（operator=系统漏洞 vullogsystem，report=WEB 漏洞 scanlogsystem），
    各自独立会话文件，互不踢号。
    """

    def __init__(self, host=VSCAN_HOST, username=VSCAN_USERNAME, password=VSCAN_PASSWORD,
                 session_file=_SESSION_FILE):
        self.host = host.rstrip('/')
        self.username = username
        self.password = password
        self._session_file = session_file
        self._lock = threading.Lock()
        self._local_session = None  # 进程内内存缓存
        self._local_ts = 0.0  # 内存缓存写入时间（必须带 TTL，否则 worker 进程存活期间永不过期）

    # ─────────── 会话管理（文件锁共享）───────────
    def _get_session(self):
        """取会话：内存（带 TTL）→ 文件（带跨进程锁）；无/过期则登录写文件
        ⚠️ 2026-08-21 修复：内存缓存必须检查 TTL——vScan cookie 25 分钟过期后，
        过期会话请求返回的是 200+空 JSON（非登录页 HTML），_get 的 HTML 检测不会触发，
        导致 stats/vulns 全部 0 且不自动续登。
        """
        if self._local_session is not None and time.time() - self._local_ts < _SESSION_TTL:
            return self._local_session
        with self._lock:
            if self._local_session is not None and time.time() - self._local_ts < _SESSION_TTL:
                return self._local_session
            self._local_session = None
            sess = self._load_from_file()
            if sess is None:
                sess = self._login_with_lock()
            self._local_session = sess
            self._local_ts = time.time()
            return sess

    def _login_with_lock(self):
        """持跨进程锁登录（防并发互踢）；登录成功写文件"""
        if fcntl is None:
            return self._login_and_save()
        try:
            os.makedirs(os.path.dirname(self._session_file), exist_ok=True)
            with open(self._session_file, 'a+') as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    # 双检：可能其他进程刚写好了
                    sess = self._load_from_file()
                    if sess is not None:
                        return sess
                    return self._login_and_save()
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except Exception as e:
            logger.warning('[vscan] 文件锁异常，直接登录: %s', e)
            return self._login_and_save()

    def _load_from_file(self):
        """从共享文件读会话；过期/损坏返回 None"""
        try:
            with open(self._session_file) as f:
                data = json.load(f)
            if time.time() - data.get('ts', 0) > _SESSION_TTL:
                return None
            s = requests.Session()
            s.verify = False
            for name, value in (data.get('cookies') or {}).items():
                s.cookies.set(name, value, domain='192.168.100.2', path='/')
            return s
        except Exception:
            return None

    def _login_and_save(self):
        """登录 vScan → 写共享文件 → 返回 Session"""
        s = self._login()
        self._save_to_file(s)
        return s

    def _save_to_file(self, s):
        data = {
            'ts': time.time(),
            'cookies': {c.name: c.value for c in s.cookies},
        }
        try:
            tmp = self._session_file + '.tmp'
            with open(tmp, 'w') as f:
                json.dump(data, f)
            os.replace(tmp, self._session_file)  # 原子替换
        except Exception as e:
            logger.warning('[vscan] 会话写文件失败: %s', e)

    def _login(self):
        """登录 vScan（免验证码，code 留空）→ 返回 requests.Session"""
        s = requests.Session()
        s.verify = False
        h0 = {'Referer': self.host + '/', 'X-Requested-With': 'XMLHttpRequest'}
        r = s.get(self.host + '/', headers=h0, timeout=VSCAN_TIMEOUT)
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
        logger.info('[vscan] 登录成功 username=%s', self.username)
        return s

    def _refresh_session(self):
        """会话失效 → 清内存缓存 + 删文件 → 重新登录（带锁）"""
        with self._lock:
            self._local_session = None
            self._local_ts = 0.0
            try:
                if os.path.exists(self._session_file):
                    os.remove(self._session_file)
            except Exception:
                pass
            sess = self._login_with_lock()
            self._local_session = sess
            self._local_ts = time.time()
            return sess

    def _get(self, path, referer, params=None, retry=True, page_url=None):
        """GET 带页面级 Referer + DataTables 参数；会话失效自动重登一次"""
        headers = {'Referer': referer, 'X-Requested-With': 'XMLHttpRequest'}
        try:
            s = self._get_session()
            if page_url:
                try:
                    s.get(self.host + page_url,
                          headers={'Referer': self.host + '/', 'X-Requested-With': 'XMLHttpRequest'},
                          timeout=VSCAN_TIMEOUT)
                except requests.RequestException:
                    pass
            r = s.get(self.host + path, headers=headers, params=params or {}, timeout=VSCAN_TIMEOUT)
        except requests.RequestException as e:
            logger.warning('[vscan] GET %s 网络错误: %s', path, e)
            if retry:
                self._refresh_session()
                return self._get(path, referer, params, retry=False, page_url=page_url)
            raise
        # 会话失效（返回 HTML）→ 重登一次
        # ⚠️ 2026-08-21 增强：JSON 接口收到任何 HTML 响应都视为会话失效——
        # vScan 的"未授权页"（session 过期/互踢）不含 username 关键词，原检测漏掉
        if r.status_code == 200 and 'text/html' in (r.headers.get('content-type') or ''):
            if retry:
                logger.info('[vscan] 会话失效（HTML 响应），重新登录后重试 %s', path)
                self._refresh_session()
                return self._get(path, referer, params, retry=False, page_url=page_url)
        return r

    # ─────────── DataTables 参数 ───────────
    @staticmethod
    def _dt_params(bregex, length=100, start=0, sort_col=1, sort_dir='desc', col_search=False):
        """构造 DataTables 服务端参数
        col_search=True  → sSearch_0=过滤条件&bRegex_0=true（漏洞列表 queryplugin 用）
        col_search=False → 全局 sSearch（任务列表 query 用，不带 bRegex）
        ⚠️ 实测铁律：任务列表接口传 bRegex=true 会被 vScan 拒绝返回 HTML（仅 sSearch 可）
        """
        p = {
            'sEcho': '1', 'iDisplayStart': str(start), 'iDisplayLength': str(length),
            'iSortCol_0': str(sort_col), 'sSortDir_0': sort_dir, 'iSortingCols': '1',
            'sColumns': '',
        }
        if col_search:
            p['sSearch_0'] = bregex
            p['bRegex_0'] = 'true'
        else:
            p['sSearch'] = bregex
        return p

    # ─────────── 业务接口 ───────────
    def task_list(self, _retry=True):
        """任务列表 → [{taskid,name,run_type,start,end,cost,progress,status,vul_cnt,type,...}]
        ⚠️ 实测：tasklist/query 用全局 sSearch（空）才返回 JSON，sSearch_0 会返回 HTML
        """
        r = self._get('/taskmgr/tasklist/query/',
                      self.host + '/taskmgr/tasklist/',
                      self._dt_params('', length=200, col_search=False),
                      page_url='/taskmgr/tasklist/')
        try:
            j = r.json()
        except Exception:
            if _retry:
                logger.info('[vscan] task_list 解析失败（疑似会话失效），强制重登重试')
                self._refresh_session()
                return self.task_list(_retry=False)
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

    def vuln_list(self, filters=None, length=100, start=0, _retry=True):
        """漏洞明细 → {total, data:[{asset_group,asset_name,ip,admin,os,severity,name,port,time,rid,detail}]}
        filters: {'assetgroup_name','asset_name','ip','adminuser_name','os','severity','name','port','from','to'}
        空过滤用 {"bRegex":"all"}
        ⚠️ 2026-08-21 兜底：vScan 会话失效时返回 200+空 JSON（iTotalRecords=0），
        _get 的 HTML 检测无法识别 → 这里 total==0 且无数据时强制重登再查一次。
        """
        cond = filters or {}
        if not any(cond.values()):
            bregex = json.dumps({'bRegex': 'all'}, ensure_ascii=False)
        else:
            bregex = json.dumps(cond, ensure_ascii=False)
        r = self._get('/statistic/vullogsystem/queryplugin/',
                      self.host + '/statistic/vullogsystem/',
                      self._dt_params(bregex, length=length, start=start, col_search=True),
                      page_url='/statistic/vullogsystem/')
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
        if _retry and total == 0 and not rows:
            logger.info('[vscan] vuln_list 返回空（疑似会话失效），强制重登重试')
            self._refresh_session()
            return self.vuln_list(filters, length=length, start=start, _retry=False)
        return {'total': total, 'data': rows}

    def vuln_detail(self, pluginid):
        """漏洞详情（描述/解决方案/CVE 等）"""
        s = self._get_session()
        headers = {'Referer': self.host + '/statistic/vullogsystem/', 'X-Requested-With': 'XMLHttpRequest'}
        try:
            r = s.post(self.host + '/hyberchannel/plugins/detail/',
                       headers=headers, data={'pluginid': pluginid}, timeout=VSCAN_TIMEOUT)
            return r.json() if r.status_code == 200 else {}
        except Exception as e:
            logger.warning('[vscan] vuln_detail %s error: %s', pluginid, e)
            return {}

    def stats(self, use_cache=True):
        """大屏统计：任务数 + 漏洞全量统计（773 条 ≈ 2 次分页）
        2026-08-21 优化：加文件缓存（TTL 60s）+ task_list/vuln_list 并发，首次 ~8s，之后秒开。
        vuln_total 用 iTotalRecords 精确总数；sev_dist / high_cnt / top_assets / recent 全量精确。
        """
        CACHE_KEY = 'stats_main'
        CACHE_TTL = 60
        if use_cache:
            hit, data = cache_get(CACHE_KEY, CACHE_TTL)
            if hit:
                return data
        from concurrent.futures import ThreadPoolExecutor
        tasks, vuln_page1 = [None], [None]
        def _tasks():
            tasks[0] = self.task_list()
        def _vulns():
            vuln_page1[0] = self.vuln_list(None, length=500, start=0)
        with ThreadPoolExecutor(max_workers=2) as ex:
            ex.submit(_tasks)
            ex.submit(_vulns)
        tasks = tasks[0] or []
        first = vuln_page1[0] or {'total': 0, 'data': []}
        total = first.get('total') or 0
        all_vulns = list(first.get('data') or [])
        # ⚠️ 2026-08-22 修复：拉满所有页算统计（vScan vullogsystem bRegex 等级过滤无效，
        # high_cnt/分布必须基于全量——否则"高危 2"远小于实际 1514 条里的高危数）
        # 全量 1514 条 ≈ 3 页 1.5s，可接受。缓存 60s 兜底刷新。
        start = 500
        while len(all_vulns) < total and start < 5000:
            res = self.vuln_list(None, length=500, start=start)
            rows = res.get('data') or []
            if not rows:
                break
            all_vulns.extend(rows)
            start += 500
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
        running = sum(1 for t in tasks if t.get('status') in (1, 2, 6))
        finished = sum(1 for t in tasks if t.get('status') in (3, 4))
        result = {
            'task_total': len(tasks),
            'task_running': running,
            'task_finished': finished,
            'vuln_total': total or len(all_vulns),
            'high_cnt': high_cnt,
            'sev_dist': sev_dist,
            'top_assets': top_assets,
            'recent': all_vulns[:20],
        }
        # ⚠️ 2026-08-24：异常结果不写缓存（iTotalRecords=0 或任务数为 0 = vScan 抖动）
        # 否则坏结果会被缓存 60s，期间所有访问大屏都看到 0
        if (result['vuln_total'] or 0) > 0 and len(tasks) > 0:
            cache_set(CACHE_KEY, result)
        else:
            logger.warning('[vscan] stats 异常（vuln_total=%s task_total=%s）跳过写缓存', result['vuln_total'], len(tasks))
        return result

    # ─────────── WEB 漏洞（scanlogsystem，report 账号）───────────
    # 2026-08-21 逆向：WEB 漏洞在 /statistic/scanlogsystem/（三级：queryindex 任务
    # → queryjob 网站[按扫描时间段] → queryplugin 漏洞明细），参数用全局 sSearch+bRegex
    # （bRegex 是过滤串，非布尔！）bRegex 格式：searchType-任务id-jobid-等级列表
    # 等级顺序与 vullogsystem 相反：0=高/1=中/2=低/3=信息
    @staticmethod
    def _scan_params(bregex, length=100, start=0, sort_col=0, sort_dir='asc'):
        """scanlogsystem 系列接口参数（全局 oSearch：sSearch 空 + bRegex=过滤串）"""
        return {
            'sEcho': '1', 'iDisplayStart': str(start), 'iDisplayLength': str(length),
            'iSortCol_0': str(sort_col), 'sSortDir_0': sort_dir, 'iSortingCols': '1',
            'sColumns': '', 'sSearch': '', 'bRegex': bregex,
        }

    def web_tasks(self, desc=True):
        """WEB 扫描任务列表 → [{taskid, name}]（queryindex searchType=0）
        ⚠️ 2026-08-21：desc=True → taskid 倒序，第一条 = 最新报告（用户约定"第一条就是最新的"）
        """
        r = self._get('/statistic/scanlogsystem/queryindex/',
                      self.host + '/statistic/scanlogsystem/',
                      self._scan_params('0', length=50, sort_dir='desc' if desc else 'asc'),
                      page_url='/statistic/scanlogsystem/')
        try:
            j = r.json()
        except Exception:
            return []
        return [{'taskid': row[0], 'name': row[1]} for row in j.get('aaData') or []]

    def web_sites(self, taskid=None):
        """WEB 网站列表（queryjob）→ [{taskid, task_name, jobid, url, start, end}]
        taskid=None → 并发遍历全部 WEB 任务（2026-08-21：queryjob 单请求 ~17s 且忽略 length
        一次返回全部 → 串行 6 任务要 100s+ 超时，必须 ThreadPool 并发，总耗时 ~20s）
        """
        from concurrent.futures import ThreadPoolExecutor
        if taskid is not None:
            tasks = [{'taskid': taskid, 'name': ''}]
        else:
            tasks = self.web_tasks()

        def _fetch(t):
            rows = []
            try:
                r = self._get('/statistic/scanlogsystem/queryjob/',
                              self.host + '/statistic/scanlogsystem/',
                              self._scan_params('0-{}'.format(t['taskid']), length=500, start=0),
                              page_url='/statistic/scanlogsystem/')
                j = r.json()
                for row in j.get('aaData') or []:
                    url_raw = row[3] if len(row) > 3 else ''
                    # ⚠️ 2026-08-22：queryjob URL 带"网站地址"前缀，去掉
                    if url_raw.startswith('网站地址'):
                        url_raw = url_raw[4:]
                    rows.append({
                        'taskid': t['taskid'],
                        'task_name': t['name'] or (row[4] if len(row) > 4 else ''),
                        'jobid': row[2] if len(row) > 2 else '',
                        'url': url_raw,
                        'start': row[0] or '',
                        'end': row[1] or '',
                    })
            except Exception as e:
                logger.warning('[vscan] web_sites 任务 %s 拉取失败: %s', t.get('taskid'), e)
            return rows

        out = []
        with ThreadPoolExecutor(max_workers=min(len(tasks) or 1, 6)) as ex:
            for rows in ex.map(_fetch, tasks):
                out.extend(rows)
        return out

    def web_vulns(self, taskid, jobid=None, length=500, start=0, sev_only=None):
        """任务级漏洞（queryplugin bRegex=0-任务id-jobid-等级）
        ⚠️ 2026-08-21 铁律：queryplugin 是【任务级】接口——jobid=0 返回整个任务的漏洞，
        不是按网站查！之前误按网站 jobid 查询导致 total=0 且 2238 网站逐个查卡死。
        实测分页 0.4s/页，任务 19 全量 31507 条 ≈ 63 页 32s；高危（等级0）85 条秒出。
        sev_only='0' → 只返回高危（bRegex 等级段只传 0）
        → {total(原始记录数), data:[去重漏洞]}（按 风险+名称 去重，任务级接口不提供 URL）
        """
        if jobid is None or jobid == '' or jobid == 0:
            jobid = 0
        sevs = sev_only if sev_only else '0,1,2,3'
        b = '0-{}-{}-{}'.format(taskid, jobid, sevs)
        r = self._get('/statistic/scanlogsystem/queryplugin/',
                      self.host + '/statistic/scanlogsystem/',
                      self._scan_params(b, length=length, start=start),
                      page_url='/statistic/scanlogsystem/')
        try:
            j = r.json()
        except Exception:
            return {'total': 0, 'data': []}
        total = j.get('iTotalRecords') or 0
        rows = []
        seen = set()
        aa = j.get('aaData') or []
        for row in aa:
            det = row[3] if len(row) > 3 and isinstance(row[3], dict) else {}
            sev = row[0] if len(row) > 0 else ''
            name = row[1] if len(row) > 1 else ''
            url = det.get('url') or ''
            # ⚠️ 2026-08-21 v4：detail 里【有】 url 字段！去重键 = 风险+名称+URL
            # （同一漏洞×同一URL 只 1 条，不同 URL 分别显示——满足"展示漏洞URL"）
            key = (str(sev), str(name), str(url))
            if key in seen:
                continue
            seen.add(key)
            rows.append({
                'severity': sev,
                'name': name,
                'category': row[2] if len(row) > 2 else '',
                'url': url,
                'param': det.get('param') or '',
                'comment': det.get('comment') or '',
                'testcase': det.get('testcase') or '',
                'pluginid': row[4] if len(row) > 4 else '',
            })
        # ⚠️ 2026-08-21 v5：raw = 当前页【原始】行数（非去重后），分页终止判断必须用它！
        # 第一页 500 条原始全是被排序顶到前面的重复高危 → 去重后仅 25 条，
        # 用 len(rows) 判断会提前 break 只处理一页（31507 → 25 的根因）
        return {'total': total, 'data': rows, 'raw': len(aa)}

    def web_vuln_detail(self, pluginid, _retry=True):
        """WEB 漏洞详情（scanplugins/detail，注意与系统漏洞 plugins/detail 不同！）
        ⚠️ 2026-08-21：HTML 响应视为会话失效，自动重登一次（web_vulns 并发拉时易踢号）
        """
        s = self._get_session()
        headers = {'Referer': self.host + '/statistic/scanlogsystem/',
                   'X-Requested-With': 'XMLHttpRequest'}
        try:
            r = s.post(self.host + '/hyberchannel/scanplugins/detail/',
                       headers=headers, data={'pluginid': pluginid}, timeout=VSCAN_TIMEOUT)
            if r.status_code == 200 and 'text/html' in (r.headers.get('content-type') or ''):
                if _retry:
                    logger.info('[vscan] web_vuln_detail 会话失效，重登后重试 pluginid=%s', pluginid)
                    self._refresh_session()
                    return self.web_vuln_detail(pluginid, _retry=False)
                return {}
            return r.json() if r.status_code == 200 else {}
        except Exception as e:
            logger.warning('[vscan] web_vuln_detail %s error: %s', pluginid, e)
            return {}

    # ─────────── WEB 全量去重构建（后台异步）───────────
    # ⚠️ 2026-08-21 v2 架构修正：queryplugin 是【任务级】接口（jobid=0=整任务），
    # 之前误按网站逐个查（2238 次 × 17s → 卡死）。改为按任务并发分页：
    #   任务 19 全量 31507 条 ≈ 63 页 × 0.4s ≈ 32s；6 任务并发总耗时 < 1min。
    def web_full_build(self, force=False):
        """后台构建 WEB 全量去重漏洞缓存。
        返回 {'building': bool, 'done': bool, 'task_total': N, 'site_total': M, 'vuln_total': K}
        - 未构建且未在进行 → 触发构建（写 meta building=true），返回 building=true
        - 构建中 → 返回 building=true + meta 进度
        - 已构建（缓存命中）→ 返回 done=true + 数据摘要
        """
        CACHE_KEY = 'web_full'
        CACHE_TTL = 600  # 10 分钟
        meta = cache_get_meta(CACHE_KEY)
        hit, data = cache_get(CACHE_KEY, CACHE_TTL)
        if hit and not force:
            return {'building': False, 'done': True,
                    'task_total': data.get('task_total', 0),
                    'site_total': data.get('site_total', 0),
                    'vuln_total': data.get('vuln_total', 0),
                    'high_cnt': data.get('high_cnt', 0)}
        # ⚠️ #7：同步进行中避免并发登录 report 账号互踢 → 软降级（不触发构建/不登录）
        if not force and _sync_building():
            return {'building': True, 'done': False, 'syncing': True,
                    'msg': '数据同步中，请稍候再查看 WEB 全量'}
        if _is_building(meta) and not force:
            return {'building': True, 'done': False,
                    'task_total': meta.get('task_total', 0),
                    'site_total': meta.get('site_total', 0),
                    'vuln_total': meta.get('vuln_total', 0),
                    'msg': '后台构建中，请稍候'}
        # 触发构建（持锁，防并发重复触发）
        lock = cache_lock(CACHE_KEY)
        try:
            # 双检：可能刚被别的 worker 触发
            meta = cache_get_meta(CACHE_KEY)
            if _is_building(meta) and not force:
                return {'building': True, 'done': False, 'msg': '后台构建中，请稍候'}
            cache_set_meta(CACHE_KEY, {'building': True, 'task_total': 0,
                                       'site_total': 0, 'vuln_total': 0,
                                       'ts': time.time(), 'err': ''})
            # 异步执行（线程，不阻塞请求）
            t = threading.Thread(target=self._web_full_build_worker, daemon=True)
            t.start()
            return {'building': True, 'done': False, 'msg': '已开始后台构建'}
        finally:
            if lock and fcntl is not None:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            if lock:
                lock.close()

    def _web_full_build_worker(self):
        """后台 worker：按任务并发拉全量漏洞 → 去重 → 写缓存
        步骤：web_sites 拿网站数（~20s）→ 按任务并发 queryplugin 分页（~30-60s）→ 去重写缓存
        """
        CACHE_KEY = 'web_full'
        try:
            tasks = self.web_tasks()
            try:
                sites = self.web_sites()
                site_total = len(sites)
            except Exception:
                site_total = 0
            cache_set_meta(CACHE_KEY, {'building': True, 'task_total': len(tasks),
                                       'site_total': site_total, 'vuln_total': 0,
                                       'ts': time.time(), 'err': ''})
            from concurrent.futures import ThreadPoolExecutor
            def _fetch_task(t):
                """按任务分页拉全量漏洞（0.4s/页），去重返回
                ⚠️ v5：分页终止判断用 raw（原始行数），不是去重后 len(rows)"""
                tid = t['taskid']
                out = []
                seen = set()
                start = 0
                while True:
                    res = self.web_vulns(tid, 0, length=500, start=start)
                    rows = res.get('data') or []
                    raw = res.get('raw') or 0
                    if not rows:
                        break
                    for r in rows:
                        key = (str(r.get('severity')), str(r.get('name')), str(r.get('url')))
                        if key in seen:
                            continue
                        seen.add(key)
                        r2 = dict(r)
                        r2['taskid'] = tid
                        out.append(r2)
                    if raw < 500:
                        break
                    start += 500
                return out
            all_vulns = []
            with ThreadPoolExecutor(max_workers=min(len(tasks) or 1, 6)) as ex:
                for rows in ex.map(_fetch_task, tasks):
                    all_vulns.extend(rows)
            # 跨任务再按 name+sev 去重
            uniq = {}
            high_cnt = 0
            for v in all_vulns:
                key = (str(v.get('severity')), str(v.get('name')), str(v.get('url')))
                if key not in uniq:
                    uniq[key] = v
                    if str(v.get('severity')) == '0':
                        high_cnt += 1
            deduped = list(uniq.values())
            result = {
                'task_total': len(tasks),
                'site_total': site_total,
                'vuln_total': len(deduped),
                'high_cnt': high_cnt,
                'data': deduped,
            }
            cache_set(CACHE_KEY, result)
            cache_set_meta(CACHE_KEY, {'building': False, 'task_total': len(tasks),
                                       'site_total': site_total,
                                       'vuln_total': len(deduped),
                                       'ts': time.time(), 'err': ''})
            logger.info('[vscan] web_full 构建完成：%d 任务 / %d 网站 / %d 去重漏洞',
                        len(tasks), site_total, len(deduped))
        except Exception as e:
            logger.exception('[vscan] web_full 构建失败')
            cache_set_meta(CACHE_KEY, {'building': False, 'task_total': 0,
                                       'site_total': 0, 'vuln_total': 0,
                                       'ts': time.time(), 'err': str(e)})

    def web_full_get(self):
        """取已构建的全量去重漏洞（缓存命中才返回，否则返回 None）"""
        hit, data = cache_get('web_full', 600)
        if hit:
            return data
        return None

    def web_high_vulns(self, taskid=None):
        """WEB 高危漏洞实时查询（等级 0 高）：按任务并发拉 → 去重（秒级）
        ⚠️ v2：按任务查（jobid=0 + sev_only='0'），不再按网站。
        """
        from concurrent.futures import ThreadPoolExecutor
        if taskid is not None:
            tasks = [{'taskid': taskid, 'name': ''}]
        else:
            tasks = self.web_tasks()
        all_high = []
        with ThreadPoolExecutor(max_workers=min(len(tasks) or 1, 6)) as ex:
            for rows in ex.map(lambda t: self.web_task_vulns(t['taskid'], sev_only='0'), tasks):
                all_high.extend(rows)
        # 跨任务再按 name+sev+url 去重
        uniq = {}
        for v in all_high:
            key = (str(v.get('severity')), str(v.get('name')), str(v.get('url')))
            if key not in uniq:
                uniq[key] = v
        return {'high_total': len(uniq), 'data': list(uniq.values())}

    def web_task_vulns(self, taskid, sev_only=None):
        """任务级漏洞（queryplugin 分页 + 按 风险+名称+URL 去重）→ [漏洞列表]
        单页 0.4s；任务 19 全量 31507 条 ≈ 63 页 32s；高危（等级0）85 条秒级。
        sev_only='0' → 只查等级 0
        ⚠️ 2026-08-21 v5：分页终止判断用 res['raw']（原始行数），不是 len(rows)（去重后）——
        第一页 500 条原始去重后仅 25 条，用 len(rows) 会提前 break 只处理一页！
        任务 19 全量 31507 条 → 837 去重（62s，缓存 300s 兜底）
        """
        CACHE_KEY = 'web_task_vulns_{}_{}'.format(taskid, sev_only or 'all')
        hit, data = cache_get(CACHE_KEY, 300)
        if hit:
            return data
        out = []
        seen = set()
        start = 0
        while True:
            res = self.web_vulns(taskid, 0, length=500, start=start, sev_only=sev_only)
            rows = res.get('data') or []
            raw = res.get('raw') or 0
            if not rows:
                break
            for r in rows:
                key = (str(r.get('severity')), str(r.get('name')), str(r.get('url')))
                if key in seen:
                    continue
                seen.add(key)
                r2 = dict(r)
                r2['taskid'] = taskid
                out.append(r2)
            if raw < 500:
                break
            start += 500
        cache_set(CACHE_KEY, out)
        return out

    def web_task_cards(self):
        """WEB 任务列表（在线查询第一屏）：任务 desc 排序（第一条=最新报告）
        每任务：网站数（web_sites 并发 ~20s，缓存 60s）+ 漏洞总数/高危数（queryplugin iTotalRecords 秒级）
        返回 {'task_total': N, 'cards': [{taskid,name,site_total,vuln_total,high_total}]}
        """
        CACHE_KEY = 'web_cards'
        CACHE_TTL = 60
        hit, data = cache_get(CACHE_KEY, CACHE_TTL)
        if hit:
            return data
        tasks = self.web_tasks(desc=True)  # 第一条 = 最新报告
        try:
            sites = self.web_sites()  # 并发 ~20s（vScan queryjob 慢，缓存 60s 兜底）
        except Exception:
            sites = []
        site_by_task = {}
        for s in sites:
            site_by_task.setdefault(str(s['taskid']), []).append(s)
        cards = []
        for t in tasks:
            tid = str(t['taskid'])
            vuln_total = 0
            high_total = 0
            try:
                res = self.web_vulns(t['taskid'], 0, length=1, start=0)
                vuln_total = res.get('total') or 0
                res_h = self.web_vulns(t['taskid'], 0, length=1, start=0, sev_only='0')
                high_total = res_h.get('total') or 0
            except Exception:
                pass
            cards.append({
                'taskid': t['taskid'],
                'name': t['name'],
                'site_total': len(site_by_task.get(tid, [])),
                'vuln_total': vuln_total,
                'high_total': high_total,
            })
        result = {'task_total': len(cards), 'cards': cards}
        cache_set(CACHE_KEY, result)
        return result


# 模块级单例
_client = None
_client_lock = threading.Lock()
_report_client = None
_report_client_lock = threading.Lock()


def get_client():
    global _client
    if _client is None:
        with _client_lock:
            if _client is None:
                _client = VScanClient()
    return _client


def get_report_client():
    """report 账号客户端（WEB 漏洞 scanlogsystem 专用，独立会话不与 operator 互踢）"""
    global _report_client
    if _report_client is None:
        with _report_client_lock:
            if _report_client is None:
                _report_client = VScanClient(
                    username=VSCAN_REPORT_USERNAME,
                    password=VSCAN_REPORT_PASSWORD,
                    session_file=_SESSION_FILE_REPORT,
                )
    return _report_client
