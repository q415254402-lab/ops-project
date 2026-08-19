# -*- coding: utf-8 -*-

from django.urls import include, re_path
from django.contrib import admin
from django.views.decorators.csrf import csrf_exempt
from apps.cmdb.api.control_api import control_api_router

urlpatterns = [
    # Django Admin
    re_path(r'^admin/', admin.site.urls),

    # OpsAny 统一认证（复用框架的 account 模块，平台会话 Cookie 认证）
    re_path(r'^account/', include('blueapps.account.urls')),

    # v4 直接搬运 control dist：baseURL = /api/v1/control/v0_1/<path>
    # control 前端是 ant-design-pro 1.x，axios POST 不带 csrftoken（依赖平台会话 bk_token）；
    # 这里 csrf_exempt 跳过 Django 全局 CSRF 中间件（403 Forbidden 修复）。
    # OpsAny 平台已做 SSO 认证，CSRF 防护由平台网关处理。
    re_path(r'^api/v1/control/v0_1/(?P<path>.+)$', csrf_exempt(control_api_router)),

    # eSight 业务 API
    re_path(r'^api/v1/cmdb/', include('apps.cmdb.urls')),
    re_path(r'^api/v1/alarms/', include('apps.alarm.urls')),
    re_path(r'^api/v1/topology/', include('apps.topology.urls')),
    re_path(r'^api/v1/discovery/', include('apps.discovery.urls')),
    re_path(r'^api/v1/performance/', include('apps.performance.urls')),
    re_path(r'^api/v1/config/', include('apps.config_management.urls')),
    re_path(r'^api/v1/network/', include('apps.network.urls')),
    re_path(r'^api/v1/reports/', include('apps.report.urls')),
    re_path(r'^api/v1/system/', include('apps.system.urls')),
    re_path(r'^api/v1/dashboard/', include('apps.dashboard.urls')),

    # 平台入口（前端 SPA 入口页面）
    re_path(r'^', include('index.urls')),
]
