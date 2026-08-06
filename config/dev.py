# -*- coding: utf-8 -*-
import os

from config import APP_CODE, BASE_DIR, BK_URL, RUN_VER  # noqa: F401

if RUN_VER == 'open':
    from blueapps.patch.settings_open_saas import *  # noqa
else:
    from blueapps.patch.settings_paas_services import *  # noqa

# 本地开发环境
RUN_MODE = 'DEVELOP'

# APP 本地静态资源目录
STATIC_URL = '/static/'

# 上传路径（本地开发环境）
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

# ============================================================
# Celery 消息队列
# ============================================================
BROKER_URL = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0')

DEBUG = True

# ============================================================
# 本地开发数据库设置
# ============================================================
# 创建数据库：
# CREATE DATABASE `esight` DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci;
# GRANT ALL ON esight.* TO esight@'%' IDENTIFIED BY "your_password";
# GRANT ALL ON esight.* TO opsany@'%';
# FLUSH PRIVILEGES;

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': APP_CODE,
        'USER': os.getenv('DB_USER', 'esight'),
        'PASSWORD': os.getenv('DB_PASSWORD', 'your_password'),
        'HOST': os.getenv('DB_HOST', 'localhost'),
        'PORT': os.getenv('DB_PORT', '3306'),
        'OPTIONS': {
            'charset': 'utf8mb4',
            'init_command': "SET sql_mode='STRICT_TRANS_TABLES'",
        },
    },
}

# ============================================================
# Redis 配置（缓存和告警去重）
# ============================================================
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = os.getenv('REDIS_PORT', '6379')
REDIS_DB = os.getenv('REDIS_DB', '0')

CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': f'redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}',
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        },
    }
}

# 线上 bk_token，本地调试使用（从 OpsAny 线上接口请求头 cookie 中获取）
BK_TOKEN = os.getenv('BK_TOKEN', 'your-bk-token-here')

# SITE_URL 本地调试指定为空
SITE_URL = {'SITE_URL': ''}

# ============================================================
# 跨域配置（本地前端 dev server 跨域调试用）
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
# 引入全局配置（INSTALLED_APPS / REST_FRAMEWORK / ESIGHT_CONFIG /
# CELERY_BEAT_SCHEDULE / LOGGING 等）
# ============================================================
from config.default import *  # noqa
