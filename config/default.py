# -*- coding: utf-8 -*-
"""
eSight 全局配置（OpsAny 后端框架）

本文件被 config/dev.py、config/prod.py、config/stag.py 引入，承载与运行环境
无关的通用配置。环境相关配置（数据库、Redis、BK_TOKEN、上传目录等）仍由各
环境配置文件负责。

统一按照《OpsAny 开发手册》的 SaaS 后端框架组织：
- 应用基本信息（APP_CODE / SECRET_KEY / BK_URL / BASE_DIR / RUN_VER）见 config/__init__.py
- 各环境在导入 blueapps 框架补丁后，再 ``from config.default import *`` 引入本文件
"""
import logging
import os

from config import APP_CODE, BASE_DIR  # noqa: F401

# ============================================================
# 时区 / 语言 / 编码
# ============================================================
LANGUAGE_CODE = 'zh-hans'
TIME_ZONE = 'Asia/Shanghai'
USE_I18N = True
USE_TZ = True

# Django 3.2 推荐的主键自增类型，避免系统警告
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# ============================================================
# 模板与静态资源
# ============================================================
STATIC_URL = '/static/'

# ============================================================
# 主路由（融合部署：SPA 入口 + 业务 API + 平台 base API）
# ============================================================
ROOT_URLCONF = 'urls'

# ============================================================
# 业务 App（在 blueapps 框架 App 基础上追加）
# ============================================================
INSTALLED_APPS += [  # noqa: F405
    'apps.cmdb',
    'apps.discovery',
    'apps.topology',
    'apps.alarm',
    'apps.performance',
    'apps.config_management',
    'apps.network',
    'apps.report',
    'apps.system',
    'apps.dashboard',
]

# ============================================================
# DRF 配置（统一认证 / 权限 / 异常处理）
# OpsAny 通过平台会话（Cookie）认证，使用 SessionAuthentication；
# 异常统一走 component.exception_handler，以对齐前端错误格式。
# ============================================================
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20,
    'DEFAULT_FILTER_BACKENDS': [
        'django_filters.rest_framework.DjangoFilterBackend',
        'rest_framework.filters.SearchFilter',
        'rest_framework.filters.OrderingFilter',
    ],
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
        'rest_framework.renderers.BrowsableAPIRenderer',
    ],
    'EXCEPTION_HANDLER': 'component.exception_handler.custom_exception_handler',
}

# ============================================================
# eSight 业务配置（SNMP / 告警 / 备份等），全部走环境变量
# ============================================================
ESIGHT_CONFIG = {
    'TRAP_PORT': int(os.getenv('TRAP_PORT', '162')),
    'SYSLOG_PORT': int(os.getenv('SYSLOG_PORT', '514')),
    'DEFAULT_SNMP_COMMUNITY': os.getenv('DEFAULT_SNMP_COMMUNITY', 'public'),
    'ENCRYPT_KEY': os.getenv('ENCRYPT_KEY', 'change-this-to-32-byte-key!!!!'),
    'METRIC_RETENTION_DAYS': int(os.getenv('METRIC_RETENTION_DAYS', '90')),
    'ALARM_HISTORY_DAYS': int(os.getenv('ALARM_HISTORY_DAYS', '365')),
    'CONFIG_BACKUP_VERSIONS': int(os.getenv('CONFIG_BACKUP_VERSIONS', '30')),
}

# ============================================================
# 日志
# ============================================================
LOG_DIR = os.path.join(BASE_DIR, 'logs')
if not os.path.exists(LOG_DIR):
    try:
        os.makedirs(LOG_DIR)
    except OSError:
        pass

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '[{asctime}] [{levelname}] [{name}] {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
        'file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join(LOG_DIR, f'{APP_CODE}-django.log'),
            'maxBytes': 10 * 1024 * 1024,
            'backupCount': 5,
            'formatter': 'verbose',
        },
        'alarm_file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join(LOG_DIR, f'{APP_CODE}-alarm.log'),
            'maxBytes': 10 * 1024 * 1024,
            'backupCount': 10,
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
        },
        'esight': {
            'handlers': ['console', 'file'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'esight.alarm': {
            'handlers': ['console', 'alarm_file'],
            'level': 'DEBUG',
            'propagate': False,
        },
    },
}

# ============================================================
# Celery 定时任务（采集 / LLDP / 拓扑 / 设备同步 / 发现）
# 若 blueapps 框架已定义 CELERY_BEAT_SCHEDULE，则在其基础上追加；
# 否则新建。
# ============================================================
_ESIGHT_BEAT = {
    'run-all-collect-tasks': {
        'task': 'apps.performance.tasks.run_all_collect_tasks',
        'schedule': 300.0,
    },
    'collect-all-lldp': {
        'task': 'apps.topology.tasks.collect_all_lldp',
        'schedule': 3600.0,
    },
    'refresh-topology-status': {
        'task': 'apps.topology.tasks.refresh_topology_status',
        'schedule': 300.0,
    },
    'sync-all-devices': {
        'task': 'apps.cmdb.tasks.sync_devices',
        'schedule': 1800.0,
    },
    'scheduled-discovery': {
        'task': 'apps.discovery.tasks.scheduled_discovery',
        'schedule': 600.0,
    },
}
try:
    CELERY_BEAT_SCHEDULE.update(_ESIGHT_BEAT)  # noqa: F405
except NameError:
    CELERY_BEAT_SCHEDULE = _ESIGHT_BEAT

# ============================================================
# Celery 启用声明（按 OpsAny 新手指南「配置修改」章节）
# - IS_USE_CELERY: 启用 celery（平台据此拉起 worker/beat）
# - CELERY_IMPORTS: 声明业务 celery 任务模块，确保 worker 能加载任务
# ============================================================
IS_USE_CELERY = True

CELERY_IMPORTS = [
    'apps.cmdb.tasks',
    'apps.performance.tasks',
    'apps.topology.tasks',
    'apps.discovery.tasks',
]
