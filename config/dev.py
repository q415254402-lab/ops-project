# -*- coding: utf-8 -*-
import os

from config import APP_CODE, BASE_DIR, BK_URL, RUN_VER  # noqa: F401

if RUN_VER == 'open':
    from blueapps.patch.settings_open_saas import *  # noqa
else:
    from blueapps.patch.settings_paas_services import *  # noqa

# 本地开发环境标记
RUN_MODE = 'DEVELOP'
DEBUG = True

# APP 本地静态资源目录
STATIC_URL = '/static/'

# 上传路径（部署环境由平台提供 /opt/opsany）
UPLOAD_PATH = os.getenv('UPLOAD_PATH', '/opt/opsany')
UPLOAD_SCRIPT_PATH = os.path.join('uploads', APP_CODE, 'script')
UPLOAD_COMMAND_PATH = os.path.join('uploads', APP_CODE, 'command')

PATH_LIST = [
    os.path.join(UPLOAD_PATH, UPLOAD_SCRIPT_PATH),
    os.path.join(UPLOAD_PATH, UPLOAD_COMMAND_PATH),
]

for PATH in PATH_LIST:
    if not os.path.exists(PATH):
        os.makedirs(PATH)

# 线上 bk_token，本地调试使用（从 OpsAny 线上接口请求头 cookie 中获取）
BK_TOKEN = os.getenv('BK_TOKEN', 'your-bk-token-here')

# SITE_URL 本地调试指定为空
SITE_URL = {'SITE_URL': ''}

# ============================================================
# 跨域配置（平台同源一般无需，放开便于本地前端联调/健康检查）
# ============================================================
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOWED_ORIGINS = ()

CORS_ALLOW_METHODS = (
    'DELETE', 'GET', 'OPTIONS', 'PATCH', 'POST', 'PUT', 'VIEW',
)

CORS_ALLOW_HEADERS = (
    'accept', 'accept-encoding', 'authorization', 'content-type',
    'dnt', 'origin', 'user-agent', 'x-csrftoken', 'x-requested-with',
)

# ============================================================
# 引入全局配置（INSTALLED_APPS / CACHES / REST_FRAMEWORK / ESIGHT_CONFIG /
# CELERY_BEAT_SCHEDULE / LOGGING / BROKER_URL 等）
# ============================================================
from config.default import *  # noqa

# ============================================================
# 开发环境数据库（按 OpsAny 新手指南「配置修改」章节）
# 优先读取环境变量；未配置时自动降级为 sqlite，保证零配置可启动。
# 正式/测试环境请在 OpsAny 控制台「应用详情-环境变量」配置 MYSQL_* 后重启。
# ============================================================
import sys as _sys

_DB_HOST_ENVS = ('MYSQL_HOST', 'DB_HOST', 'BKAPP_DB_HOST', 'BKPAAS_MYSQL_HOST', 'MYSQL_SERVER_IP')
_DB_HOST = _first_env(*_DB_HOST_ENVS)

if _DB_HOST:
    DATABASES = {
        'default': {
            'ENGINE': os.getenv('DB_ENGINE', 'django.db.backends.mysql'),
            'NAME': _first_env('MYSQL_NAME', 'DB_NAME', 'BKAPP_DB_NAME', 'BKPAAS_MYSQL_NAME', default=APP_CODE),
            'USER': _first_env('MYSQL_USER', 'DB_USER', 'BKAPP_DB_USERNAME', 'BKPAAS_MYSQL_USER', default='opsany'),
            'PASSWORD': _first_env('MYSQL_PASSWORD', 'DB_PASSWORD', 'BKAPP_DB_PASSWORD', 'BKPAAS_MYSQL_PASSWORD', default=''),
            'HOST': _DB_HOST,
            'PORT': _first_env('MYSQL_PORT', 'DB_PORT', 'BKAPP_DB_PORT', 'BKPAAS_MYSQL_PORT', default='3306'),
            'OPTIONS': {
                'charset': 'utf8mb4',
                'init_command': "SET sql_mode='STRICT_TRANS_TABLES'",
            },
        }
    }
else:
    _SQLITE_PATH = os.getenv('ESIGHT_SQLITE_PATH', '/opt/opsany/esight-%s.sqlite3' % APP_CODE)
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': _SQLITE_PATH,
        }
    }
    _sys.stderr.write(
        "\n[esight][INFO] 未检测到数据库环境变量(%s)，已自动使用 sqlite 文件库: %s\n"
        "          正式环境请在 OpsAny 控制台 esight 应用详情-环境变量中配置 MYSQL_HOST/MYSQL_PORT/"
        "MYSQL_USER/MYSQL_PASSWORD/MYSQL_NAME 并建好库后重启应用，自动切换 MySQL。\n"
        % ('/'.join(_DB_HOST_ENVS), _SQLITE_PATH)
    )

# 开发环境消息队列：优先平台注入的 BK_BROKER_URL / CELERY_BROKER_URL，
# 否则沿用 default.py 根据 REDIS 自动降级后的 BROKER_URL（memory://）。
BROKER_URL = os.getenv('BK_BROKER_URL') or os.getenv('CELERY_BROKER_URL') or BROKER_URL
CELERY_BROKER_URL = BROKER_URL
