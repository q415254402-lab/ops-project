# -*- coding: utf-8 -*-
"""
网络安全设备 - WAF 攻击日志模型（2026-08-17）
数据来源：绿盟日志审计系统（LAS, 192.168.99.11）Syslog 转发
格式：绿盟标准 Key-Value（见《绿盟日志转发格式规范》），字段做兼容映射：
  sip→src_ip  dip→dst_ip  sport→src_port  dport→dst_port
  gr_type_mapping→event_type  gr_danger_mapping→severity  action_mapping→action
  date→log_time  msg→msg  dev_ip→dev_ip  rule_id→rule_id
WAF 特有：method/domain/uri（HTTP 攻击日志）
"""
from django.db import models


class WafAttackLog(models.Model):
    """安全设备攻击日志（syslog 接收落库）——WAF/防火墙通用（device_type 区分）"""
    device_type = models.CharField('设备类型', max_length=32, blank=True, default='WAF', db_index=True)
    log_time = models.DateTimeField('日志时间', db_index=True)
    dev_ip = models.CharField('设备IP', max_length=64, blank=True, default='', db_index=True)
    dev_id = models.CharField('设备HASH', max_length=64, blank=True, default='')
    src_ip = models.CharField('源IP', max_length=64, blank=True, default='', db_index=True)
    src_port = models.CharField('源端口', max_length=16, blank=True, default='')
    dst_ip = models.CharField('目的IP', max_length=64, blank=True, default='', db_index=True)
    dst_port = models.CharField('目的端口', max_length=16, blank=True, default='')
    event_type = models.CharField('攻击类型', max_length=128, blank=True, default='', db_index=True)
    event_type_id = models.IntegerField('攻击类型ID', default=0)
    severity = models.CharField('危险等级', max_length=32, blank=True, default='')
    severity_id = models.IntegerField('危险等级ID', default=0)
    action = models.CharField('处置动作', max_length=32, blank=True, default='')
    action_id = models.IntegerField('动作ID', default=0)
    msg = models.TextField('事件描述', blank=True, default='')
    rule_id = models.CharField('规则ID', max_length=64, blank=True, default='')
    proto = models.CharField('协议', max_length=32, blank=True, default='')
    # WAF HTTP 字段
    method = models.CharField('HTTP方法', max_length=16, blank=True, default='')
    domain = models.CharField('域名', max_length=255, blank=True, default='')
    uri = models.TextField('URL', blank=True, default='')
    # 原始日志
    raw = models.TextField('原始日志', blank=True, default='')
    # 2026-08-17：WAF 扩展字段（站点/国家/协议/告警信息/策略名）
    site_name = models.CharField('站点名称', max_length=255, blank=True, default='')
    src_country = models.CharField('源国家', max_length=128, blank=True, default='')
    protocol_type = models.CharField('协议类型', max_length=32, blank=True, default='')
    alert_info = models.CharField('告警信息', max_length=255, blank=True, default='')
    policy_name = models.CharField('策略名称', max_length=255, blank=True, default='')
    created_at = models.DateTimeField('入库时间', auto_now_add=True)

    class Meta:
        db_table = 'cmdb_waf_attack_log'
        verbose_name = 'WAF攻击日志'
        verbose_name_plural = verbose_name
        ordering = ['-log_time']
        indexes = [
            models.Index(fields=['log_time', 'src_ip']),
            models.Index(fields=['dev_ip', 'log_time']),
            models.Index(fields=['device_type', 'log_time']),
        ]

    def __str__(self):
        return f'{self.log_time} {self.src_ip} -> {self.dst_ip} {self.event_type}'
