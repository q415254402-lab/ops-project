# -*- coding: utf-8 -*-
"""
eSight 全局配置（OpsAny 后端框架）

按《OpsAny 开发手册》的 SaaS 后端框架组织：
- config/__init__.py 提供 APP_CODE / SECRET_KEY / BK_URL / BASE_DIR / RUN_VER / get_env_or_raise
- 本文件先 ``from blueapps.conf.default_settings import *`` 引入 blueapps 标准默认配置
  （INSTALLED_APPS / MIDDLEWARE / TEMPLATES / AUTH_USER_MODEL / BK_URL / RUN_VER /
  STATIC_URL 等），再追加 eSight 业务配置。
- config/dev.py 在导入 blueapps 框架补丁（settings_open_saas）后，再
  ``from config.default import *`` 引入本文件。
"""
import logging
import os
import sys as _sys

from blueapps.conf.default_settings import *  # noqa: F401,F403

# 重新固定为项目自身值（blueapps 默认可能来自 environ，需以本项目 __init__ 为准）
from config import APP_CODE, BASE_DIR, RUN_VER, BK_URL  # noqa: F401


def _first_env(*names, default=''):
    """读取第一个非空环境变量，都没有则返回 default。"""
    for _n in names:
        _v = os.getenv(_n)
        if _v:
            return _v
    return default

# OpsAny open SaaS 运行版本与平台地址（部署时由平台注入 BK_URL / BK_PAAS_HOST）
RUN_VER = 'open'
BK_URL = os.getenv('BK_URL') or os.getenv('BK_PAAS_HOST') or 'https://192.168.99.31'

# ============================================================
# 登录相关（平台不注入 blueking.component，ESB SDK 不可用）
# ============================================================
# ESB SDK 指向项目内 shim（esb_shim/）：blueapps 登录校验 bk_token 时，
# shim 的 is_login 抛 NotImplementedError → blueapps 自动 fallback 到 verify_url
# （直接调平台登录 /accounts/is_login/），get_user 由 shim 直连平台 /accounts/get_user/。
ESB_SDK_NAME = 'esb_shim'

# 平台注入的 BK_PAAS2_INNER_URL 可能是不可达的外部域名（如 dev.opsany.cn），
# 导致 verify_url 校验 bk_token 时连接超时、登录挂起；内部登录地址优先取外部可达的
# BKPAAS_LOGIN_URL / BK_PAAS2_URL（实测 192.168.99.31/login 下 /accounts/is_login|get_user/ 可达）。
# 注意：本文件被 blueapps patch 单独导入，不能引用 patch 才设置的变量（如 BK_LOGIN_URL）。
BK_LOGIN_INNER_URL = (
    os.getenv('BKPAAS_LOGIN_URL') or (os.getenv('BK_PAAS2_URL') or BK_URL).rstrip('/') + '/login'
).rstrip('/')
if 'opsany.cn' in BK_LOGIN_INNER_URL or not BK_LOGIN_INNER_URL.startswith('http'):
    BK_LOGIN_INNER_URL = BK_URL.rstrip('/') + '/login'

# 平台 nginx 未剥离 /t/<app_code>/ 前缀时，SITE_URL(=BKPAAS_SUB_PATH) 与请求 path
# 叠加导致登录回调 c_url 出现 /t/esight/t/esight/... 无限叠加；置空以使用请求自身 path。
SITE_URL = ''
FORCE_SCRIPT_NAME = ''

# ============================================================
# 中间件：平台应用前缀剥离
# ============================================================
# 容器 nginx 将 /t/<app_code>/ 或 /o/<app_code>/ 前缀原样转发给 uwsgi（不设
# SCRIPT_NAME、不剥前缀），Django 收到的 PATH_INFO 带前缀导致 API/后台路由全部
# 落到 catch-all 返回 SPA index.html。将本中间件置于最前：PATH_INFO 剥前缀供
# URL 解析，SCRIPT_NAME 设为前缀保持 request.path（登录回调 c_url）不变。
# 注意：blueapps 默认 MIDDLEWARE 是 tuple，须用元组拼接。
MIDDLEWARE = ('middleware.StripSitePrefixMiddleware',) + MIDDLEWARE  # noqa: F405

# ============================================================
# 时区 / 语言 / 编码
# ============================================================
LANGUAGE_CODE = 'zh-hans'
TIME_ZONE = 'Asia/Shanghai'
USE_I18N = True
USE_TZ = True

# Django 推荐的主键自增类型，避免系统警告
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# blueapps 模板上下文处理器 blue_settings 读取该配置（静态资源版本号，模板拼
# 接资源 URL ?v=；缺失会报 'Settings' object has no attribute 'STATIC_VERSION'）
STATIC_VERSION = os.getenv('STATIC_VERSION', '1.0')

# blueapps.account 的 migration 0002_init_superuser 会读取该配置，
# 把列出的平台用户名提升为超级管理员（OpsAny 默认平台管理员为 admin）。
INIT_SUPERUSER = ["admin"]

# ============================================================
# 模板与静态资源
# ============================================================
STATIC_URL = '/static/'

# 融合部署产物：前端构建输出到 static/esight/（SPA 静态资源）与
# templates/index.html（SPA 入口）。STATICFILES_DIRS 让 collectstatic 能收集到，
# STATIC_ROOT 为 collectstatic 目标（whitenoise 按 STATIC_URL 提供）。
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATICFILES_DIRS = [os.path.join(BASE_DIR, 'static')]
# 该 OpsAny paas-agent 部署流程不执行 collectstatic（staticfiles/ 目录为空），
# 开启 finders 模式让 whitenoise 直接从 STATICFILES_DIRS(static/esight) 提供前端产物
WHITENOISE_USE_FINDERS = True

# 主路由（融合部署：SPA 入口 + 业务 API）
ROOT_URLCONF = 'urls'

# ============================================================
# 业务 App（在 blueapps 默认 INSTALLED_APPS 基础上追加）
# 注意：blueapps 默认已包含 bkoauth / blueapps.account 等；
# settings_open_saas 补丁会自动移除 bkoauth（open 环境不需要）。
# ============================================================
INSTALLED_APPS = INSTALLED_APPS + (  # noqa: F405
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
)

# ============================================================
# Redis / Celery 消息队列
# ============================================================
REDIS_HOST = _first_env('REDIS_HOST', 'BKAPP_REDIS_HOST')

if REDIS_HOST:
    # 显式配置了 Redis —— 使用 redis 缓存与消息队列
    REDIS_PORT = _first_env('REDIS_PORT', 'BKAPP_REDIS_PORT', default='6379')
    REDIS_DB = _first_env('REDIS_DB', 'BKAPP_REDIS_DB', default='0')
    REDIS_PASSWORD = os.getenv('REDIS_PASSWORD') or os.getenv('BKAPP_REDIS_PASSWORD') or ''
    if REDIS_PASSWORD:
        REDIS_LOCATION = 'redis://:%s@%s:%s/%s' % (REDIS_PASSWORD, REDIS_HOST, REDIS_PORT, REDIS_DB)
    else:
        REDIS_LOCATION = 'redis://%s:%s/%s' % (REDIS_HOST, REDIS_PORT, REDIS_DB)

    CACHES = {
        'default': {
            'BACKEND': 'django_redis.cache.RedisCache',
            'LOCATION': REDIS_LOCATION,
            'OPTIONS': {'CLIENT_CLASS': 'django_redis.client.DefaultClient'},
        },
        # blueapps.account 使用 caches['login_db']，必须保留该别名
        'login_db': {
            'BACKEND': 'django_redis.cache.RedisCache',
            'LOCATION': REDIS_LOCATION,
            'OPTIONS': {'CLIENT_CLASS': 'django_redis.client.DefaultClient'},
        },
        'db': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        },
        'dummy': {
            'BACKEND': 'django.core.cache.backends.dummy.DummyCache',
        },
        'locmem': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        },
    }
else:
    # 未配置 Redis —— 自动降级为内存缓存（保证零配置可跑；多进程/重启后缓存丢失）
    CACHES = {
        'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'},
        'login_db': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'},
        'db': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'},
        'dummy': {'BACKEND': 'django.core.cache.backends.dummy.DummyCache'},
        'locmem': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'},
    }
    REDIS_LOCATION = ''
    _sys.stderr.write(
        "[esight][INFO] 未检测到 Redis 环境变量(REDIS_HOST)，已自动使用内存缓存；"
        "正式环境配置 REDIS_HOST/REDIS_PORT/REDIS_PASSWORD 后自动切换。\n"
    )

# 消息队列：优先平台注入的 BK_BROKER_URL（OpsAny 常为 rabbitmq），否则 CELERY_BROKER_URL；
# 配置了 Redis 用 redis 兜底，否则用 memory://（不持久，仅保证进程可启动）
BROKER_URL = os.getenv('BK_BROKER_URL') or os.getenv('CELERY_BROKER_URL') or (REDIS_LOCATION or 'memory://')
CELERY_BROKER_URL = BROKER_URL
# ⚠️ 2026-08-21 修复：celery 5.3 不认 'amqp' 作为 result backend（会 "Unknown result backend: 'amqp'" 崩溃）。
# 容器里 BK_BROKER_URL=amqp://...（rabbitmq）→ 需转成 rpc:// 才合法；无 rabbitmq 时用 Redis/内存。
_BK_BROKER = os.getenv('BK_BROKER_URL') or ''
CELERY_RESULT_BACKEND = os.getenv('CELERY_RESULT_BACKEND') or (
    _BK_BROKER.replace('amqp://', 'rpc://', 1) if _BK_BROKER.startswith('amqp://') else REDIS_LOCATION
)

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
    'EXCEPTION_HANDLER': 'rest_framework.views.exception_handler',
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
            'filename': os.path.join(LOG_DIR, '%s-django.log' % APP_CODE),
            'maxBytes': 10 * 1024 * 1024,
            'backupCount': 5,
            'formatter': 'verbose',
        },
        'alarm_file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join(LOG_DIR, '%s-alarm.log' % APP_CODE),
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
# 在 blueapps 框架已定义的 CELERY_BEAT_SCHEDULE 基础上追加
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
    'security-alert-scan': {
        'task': 'apps.cmdb.tasks.alert_scan',
        'schedule': 60.0,  # beat 每分钟触发；任务内部按 AlertRule.scan_interval_minutes 节流
    },
    'scheduled-discovery': {
        'task': 'apps.discovery.tasks.scheduled_discovery',
        'schedule': 600.0,
    },
    'security-report-gen': {
        'task': 'apps.cmdb.tasks.gen_reports',
        'schedule': 3600.0,
    },
    # 2026-09-04：日报历史回填（从数据源最早日到昨天，上限 30 天，幂等）
    'security-report-backfill': {
        'task': 'apps.cmdb.tasks.backfill_reports',
        'schedule': 86400.0,
    },
    # 2026-09-04：保留策略清理（日报 90 / 周报 104 / 月报永久）
    'security-report-purge': {
        'task': 'apps.cmdb.tasks.purge_reports',
        'schedule': 86400.0,
    },
}
try:
    CELERY_BEAT_SCHEDULE.update(_ESIGHT_BEAT)  # noqa: F405
except NameError:
    CELERY_BEAT_SCHEDULE = _ESIGHT_BEAT

# ============================================================
# 周期任务注册 —— 关键修复（v10，2026-08-31）
# ------------------------------------------------------------
# 根因：blueapps 的 celery app 用的是 ``app.config_from_object("django.conf:settings")``
# 且 namespace=None（见 site-packages/blueapps/core/celery/celery.py）。于是：
#   1) beat 实际读取的是 settings 里小写字面值 ``beat_schedule``；
#   2) Django 的 Settings 只导入「大写」配置，小写 ``beat_schedule`` 被静默丢弃；
# 两者叠加 → app.conf.beat_schedule 永远为空 → beat 一份周期任务都不注册 →
# 所有定时任务（采集 / LLDP / 拓扑 / 设备同步 / 发现 / 安全告警）全部不触发，
# 只能手动点「立即检测」。
# 直接把周期表写进 celery app 的 conf（绕过 Django 大写过滤 + settings 只读限制），
# beat 即可正确加载。不要用 on_after_finalize + add_periodic_task 注册——
# 它的回写目标是 django.conf.settings（只读），会静默失败。
# ============================================================
try:
    from blueapps.core.celery import celery_app
    celery_app.conf.update(beat_schedule=CELERY_BEAT_SCHEDULE)
except Exception:  # pragma: no cover - 注册失败不应阻断启动
    pass

# ============================================================
# Celery 启用声明（按 OpsAny 新手指南「配置修改」章节）
# ============================================================
IS_USE_CELERY = True

CELERY_IMPORTS = [
    'apps.cmdb.tasks',
    'apps.performance.tasks',
    'apps.topology.tasks',
    'apps.discovery.tasks',
]
