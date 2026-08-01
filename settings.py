# -*- coding: utf-8 -*-
"""
eSight Django Settings 入口

统一按照《OpsAny 开发手册》的 SaaS 后端框架（blueapps）组织配置：
- 通用配置见 config/default.py
- 环境配置见 config/dev.py（开发）、config/stag.py（预发）、config/prod.py（生产）

``manage.py`` / ``wsgi.py`` 默认加载本文件，即采用 config.dev（本地开发）。
部署到 OpsAny 生产环境时，请设置环境变量：

    export DJANGO_SETTINGS_MODULE=config.prod

也可按需切换为 config.stag。
"""
from config.dev import *  # noqa
