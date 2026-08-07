# -*- coding: utf-8 -*-
import os

from config import APP_CODE, BASE_DIR, RUN_VER  # noqa: F401

if RUN_VER == 'open':
    from blueapps.patch.settings_open_saas import *  # noqa
else:
    from blueapps.patch.settings_paas_services import *  # noqa

# 生产环境
RUN_MODE = 'PRODUCT'

STATIC_URL = '/static/'

DEBUG = False

# ============================================================
# 引入全局配置
# ============================================================
from config.default import *  # noqa

# ============================================================
# 正式环境数据库设置（按 OpsAny 新手指南「配置修改」章节）
# ============================================================
DATABASES = {
    'default': {
        'ENGINE': os.getenv('DB_ENGINE', 'django.db.backends.mysql'),
        'NAME': os.getenv('DB_NAME', APP_CODE),
        'USER': os.getenv('DB_USER', 'esight'),
        'PASSWORD': os.getenv('DB_PASSWORD', ''),
        'HOST': os.getenv('DB_HOST', 'localhost'),
        'PORT': os.getenv('DB_PORT', '3306'),
        'OPTIONS': {
            'charset': 'utf8mb4',
            'init_command': "SET sql_mode='STRICT_TRANS_TABLES'",
        },
    },
}

# 正式环境消息队列：优先环境变量，否则默认本地 Redis
BROKER_URL = os.getenv('BK_BROKER_URL') or os.getenv('CELERY_BROKER_URL') or 'redis://localhost:6379/0'
CELERY_BROKER_URL = BROKER_URL

# 生产环境覆盖项
REST_FRAMEWORK['DEFAULT_RENDERER_CLASSES'] = ['rest_framework.renderers.JSONRenderer']
ESIGHT_CONFIG['ENCRYPT_KEY'] = os.getenv('ENCRYPT_KEY', '')
