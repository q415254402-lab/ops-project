# -*- coding: utf-8 -*-
from __future__ import absolute_import

# 使用 PyMySQL 替代 mysqlclient（纯 Python，离线构建机无需编译 MySQL 开发库）。
# 必须在 Django 加载前注册，避免运行时报 "did you install mysqlclient"。
try:
    import pymysql
    pymysql.install_as_MySQLdb()
except ImportError:
    pass


def get_env_or_raise(key):
    """读取环境变量，缺失则直接报错退出。

    供 blueapps 框架补丁 ``blueapps.patch.settings_open_saas`` 使用：
    OpsAny 平台部署时会注入 ``BKPAAS_APP_ID`` / ``BKPAAS_APP_SECRET`` 等必填变量，
    补丁通过本函数获取这些变量，缺失即抛 ``RuntimeError``。
    """
    import os
    val = os.getenv(key)
    if not val:
        raise RuntimeError("env %s is required" % key)
    return val


__all__ = ['celery_app', 'RUN_VER', 'APP_CODE', 'SECRET_KEY', 'BK_URL', 'BASE_DIR', 'get_env_or_raise']

import os

# This will make sure the app is always imported when
# Django starts so that shared_task will use this app.
from blueapps.core.celery import celery_app

# ============================================================
# SaaS 基本信息 — 在 OpsAny 开发中心创建应用后填写
# ============================================================

# SaaS 运行版本，如非必要请勿修改
RUN_VER = 'open'

# SaaS 应用 ID（在 OpsAny 开发中心 -> 应用详情 -> 基本信息 中查看）
# 平台部署时会通过环境变量 APP_CODE / BKPAAS_APP_ID 注入；本地开发使用默认值即可。
APP_CODE = os.getenv('APP_CODE') or os.getenv('BKPAAS_APP_ID') or 'esight'

# SaaS 安全密钥 / 应用 TOKEN（在 OpsAny 开发中心 -> 应用详情 -> 基本信息 中查看）
# 平台注入的变量名可能是 SECRET_KEY / APP_TOKEN / BKPAAS_APP_SECRET，三者都兼容。
SECRET_KEY = (
    os.getenv('SECRET_KEY') or os.getenv('APP_TOKEN')
    or os.getenv('BKPAAS_APP_SECRET') or 'change-me-to-your-app-token'
)

# OpsAny 平台地址（本实例为 https://192.168.99.31）
# 兼容 BK_URL 与 BK_PAAS_HOST 两种变量名。
BK_URL = os.getenv('BK_URL') or os.getenv('BK_PAAS_HOST') or 'https://192.168.99.31'

# ============================================================
# 上传目录
# ============================================================
UPLOAD_PATH = os.getenv('UPLOAD_PATH', '/opt/opsany')

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 工作台首页默认用户图标路径
DEFAULT_USER_ICON = os.getenv(
    'DEFAULT_USER_ICON',
    'uploads/workbench/user_icon/edfb99ee-08d6-41b8-ac5f-117fb86b0912.png'
)

DEFAULT_LANGUAGE = 'chinese_simplified'
DEFAULT_THEME = 'theme-default'
