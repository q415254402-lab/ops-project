# -*- coding: utf-8 -*-
"""
eSight WSGI 入口。

双保险说明：OpsAny paas-agent 的 supervisor 硬编码从 venv 调用
``Envs/<app_code>/bin/uwsgi`` 启动本文件；若部署机 venv 因 --system-site-packages
模式未能装入 uwsgi（pip 认为系统已满足而跳过），可临时以系统 uwsgi 启动，
此时 Python 解释器看不到 venv 的 site-packages。这里在加载 Django 前把应用
venv 的 site-packages 注入 sys.path，保证两种启动方式都能正常 import 依赖。
"""
import glob
import os
import sys

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_VENV_DIR = os.path.abspath(
    os.path.join(_BASE_DIR, '..', '..', '..', '..', 'Envs', 'esight')
)
if os.path.isdir(_VENV_DIR):
    for _site in glob.glob(os.path.join(_VENV_DIR, 'lib', 'python3.*', 'site-packages')):
        if _site not in sys.path:
            sys.path.insert(0, _site)

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'settings')

from django.core.wsgi import get_wsgi_application  # noqa: E402

application = get_wsgi_application()
