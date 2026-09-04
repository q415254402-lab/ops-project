# -*- coding: utf-8 -*-
"""CMDB 周期任务包

将子模块任务统一 re-export，供 Celery Beat 以
`apps.cmdb.tasks.<func>` 形式引用。
"""
from .sync import sync_device_info, sync_all_devices, sync_devices

from .alert import alert_scan
from .report import (
    gen_reports, backfill_reports, purge_reports,
    regenerate_report_summary, backfill_day_summaries,
)
__all__ = [
    'sync_device_info', 'sync_all_devices', 'sync_devices', 'alert_scan',
    'gen_reports', 'backfill_reports', 'purge_reports', 'regenerate_report_summary',
    'backfill_day_summaries',
]
