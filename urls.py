# -*- coding: utf-8 -*-

from django.conf.urls import include, url
from django.contrib import admin

urlpatterns = [
    # Django Admin
    url(r'^admin/', admin.site.urls),

    # OpsAny 统一认证（复用框架的 account 模块，平台会话 Cookie 认证）
    url(r'^account/', include('blueapps.account.urls')),

    # eSight 业务 API
    url(r'^api/v1/cmdb/', include('apps.cmdb.urls')),
    url(r'^api/v1/alarms/', include('apps.alarm.urls')),
    url(r'^api/v1/topology/', include('apps.topology.urls')),
    url(r'^api/v1/discovery/', include('apps.discovery.urls')),
    url(r'^api/v1/performance/', include('apps.performance.urls')),
    url(r'^api/v1/config/', include('apps.config_management.urls')),
    url(r'^api/v1/network/', include('apps.network.urls')),
    url(r'^api/v1/reports/', include('apps.report.urls')),
    url(r'^api/v1/system/', include('apps.system.urls')),
    url(r'^api/v1/dashboard/', include('apps.dashboard.urls')),

    # OpsAny 框架基础 API（菜单、导航、消息、用户信息等）
    url(r'^api/base/v0_1/', include('base.urls')),

    # 平台入口（前端 SPA 入口页面）
    url(r'^', include('index.urls')),
]
