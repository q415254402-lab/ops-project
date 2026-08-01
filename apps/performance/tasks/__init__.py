# -*- coding: utf-8 -*-
"""性能采集周期任务包

将子模块任务统一 re-export，供 Celery Beat 以
`apps.performance.tasks.<func>` 形式引用。
"""
from .collect import run_all_collect_tasks, collect_metric_data

__all__ = ['run_all_collect_tasks', 'collect_metric_data']
