# -*- coding: utf-8 -*-
"""
平台应用前缀剥离中间件

问题背景：
OpsAny 容器 nginx 将 /t/<app_code>/（测试）或 /o/<app_code>/（正式）前缀
原样转发给 uwsgi —— 不设置 SCRIPT_NAME、也不剥离前缀。导致 Django 收到的
PATH_INFO 形如 '/t/esight/api/v1/cmdb/devices/'，而 urls.py 只注册了
'^api/v1/...'，永远匹配不上 → 所有 API / admin / account 路由全部落入
catch-all（re_path(r'^', IndexView)）→ 返回 SPA index.html（HTTP 200 但
Content-Type 是 text/html），前端 axios 拿到 HTML 字符串、页面永远拿不到数据。

修复思路（本中间件置于 MIDDLEWARE 最前）：
将 '/<t|o>/<app_code>/' 前缀剥离：
- PATH_INFO 去掉前缀          → Django 正确解析 URL（API / admin / account 全通）
- request.path 保持带前缀      → get_full_path() / build_absolute_uri() 带前缀，
  登录回调 c_url 不受影响（配合 FORCE_SCRIPT_NAME='' 不会叠加）
若 nginx 已正确剥离前缀（PATH_INFO 无前缀），本中间件为 no-op。

注意：Django 4.2 的 WSGIRequest 在 __init__ 时把 path/path_info 算成普通实例
属性（且 FORCE_SCRIPT_NAME 非 None 时忽略 environ 的 SCRIPT_NAME），因此本
中间件直接覆盖这两个属性并同步 META。
"""
import re

from django.conf import settings

_PREFIX_RE = re.compile(r'^/([to])/([^/]+)(/|$)')


class StripSitePrefixMiddleware:
    """剥离平台注入的应用前缀 /t/<app_code>/ 或 /o/<app_code>/。"""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path_info = request.META.get('PATH_INFO', '')
        prefix = self._match_prefix(path_info)
        if prefix:
            rest = path_info[len(prefix):]
            if not rest.startswith('/'):
                rest = '/' + rest
            script = prefix.rstrip('/')
            request.META['SCRIPT_NAME'] = script
            request.META['PATH_INFO'] = rest
            request.path_info = rest
            request.path = script + rest
        return self.get_response(request)

    def _match_prefix(self, path):
        """匹配 /<env>/<app_code>/ 前缀，返回如 '/t/esight/'；不匹配返回 None。"""
        if not path:
            return None
        m = _PREFIX_RE.match(path)
        if not m:
            return None
        app_code = getattr(settings, 'APP_CODE', 'esight')
        if m.group(2) != app_code:
            return None
        return m.group(0)
