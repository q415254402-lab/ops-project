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
# 引入全局配置（INSTALLED_APPS / DATABASES / CACHES / REST_FRAMEWORK /
# ESIGHT_CONFIG / CELERY_BEAT_SCHEDULE / LOGGING 等）
# ============================================================
from config.default import *  # noqa
