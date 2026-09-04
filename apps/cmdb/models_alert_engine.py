# -*- coding: utf-8 -*-
"""告警引擎适配层：连接 security_alert_views 的阈值工具与收敛引擎。

单独抽出的原因：
- alert_engine 需要调用 _WEB_THR / _sev_strings（定义在 views 中）；
- tasks（Celery）与 views（HTTP）都要触发扫描；
- 避免 views 与 engine 相互 import 造成循环依赖。

对外只暴露两个入口：
- run_alert_scan_manual(rule)     手动触发（trigger='manual'）
- run_alert_scan_scheduled(rule)  定时触发（trigger='scheduled'）
"""
import logging

logger = logging.getLogger('app')


def _sev_values(rule):
    """按规则阈值解析出实际 severity 取值（中英文混合）。"""
    from apps.cmdb.api.security_alert_views import _sev_strings
    return _sev_strings(rule.severity_threshold)


def run_alert_scan_manual(rule):
    """手动触发扫描（带收敛 + 恢复检测）。"""
    from apps.cmdb.alert_engine import run_converge_scan
    return run_converge_scan(rule, _sev_values(rule), trigger='manual')


def run_alert_scan_scheduled(rule):
    """定时触发扫描（带收敛 + 恢复检测）。"""
    from apps.cmdb.alert_engine import run_converge_scan
    return run_converge_scan(rule, _sev_values(rule), trigger='scheduled')


def event_stats():
    """事件中心统计卡数据（透传给 views）。"""
    from apps.cmdb.alert_engine import event_stats as _stats
    return _stats()
