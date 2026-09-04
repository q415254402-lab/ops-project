# -*- coding: utf-8 -*-
"""安全告警：规则配置 + 告警事件（生命周期）+ 扫描记录。

设计对标 Grafana Alerting / Prometheus Alertmanager 的核心模型：

- **AlertEvent（告警事件）**：具备完整生命周期的告警实体。
  以 fingerprint（归一化指纹）为唯一键，持续出现的攻击累计 occurrence 而非重复推送；
  冷却期内抑制推送但持续计数；超过 resolve_after 未复现则自动 resolved 并可选推送恢复通知。
  状态机：firing（触发中）→ acked（已确认）→ resolved（已恢复）/ suppressed（已忽略）

- **AlertRecord（扫描记录）**：每次扫描执行的审计快照，记录本次新增/恢复/抑制数量，
  用于追溯"系统在某时刻做了什么"，不承载运营状态。

- **AlertRule（告警规则）**：单例，含阈值、窗口、调度周期、冷却期、恢复判定等。

severity 说明：
- WAF/FW 的 severity 是字符串，中英文混存（'high'/'高'/'中'/空值），
  映射见 waf_views._SEV_MAP；空值在 include_unknown_severity=True 时按 'unknown' 纳入。
"""
from django.db import models


class AlertRule(models.Model):
    """单例告警规则（id=1），前端可编辑。"""
    THR_CHOICES = [
        ('low', '低及以上'),
        ('medium', '中及以上'),
        ('high', '高及以上'),
    ]
    # ---- 基础判定 ----
    severity_threshold = models.CharField('严重级别阈值', max_length=16,
                                          default='high', choices=THR_CHOICES)
    window_minutes = models.IntegerField('检测时间窗(分钟)', default=60)
    enabled = models.BooleanField('启用告警', default=True)

    # ---- 2026-08-28 深化：调度、收敛、生命周期 ----
    scan_interval_minutes = models.IntegerField('定时扫描周期(分钟)', default=60,
                                                help_text='Celery beat 调度周期；0 表示仅手动')
    cooldown_minutes = models.IntegerField('同事件冷却期(分钟)', default=60,
                                           help_text='同一 fingerprint 在冷却期内不重复推送，但持续累计次数')
    resolve_after_minutes = models.IntegerField('恢复判定时间(分钟)', default=120,
                                                help_text='事件超过该时长未再出现则判定为已恢复')
    notify_on_resolve = models.BooleanField('恢复时推送通知', default=True)
    include_unknown_severity = models.BooleanField('纳入未知级别(空severity)', default=False,
                                                   help_text='WAF/FW 存在空 severity 记录，开启后按 unknown 纳入统计')

    # ---- 推送通道 ----
    dingtalk_enabled = models.BooleanField('钉钉推送', default=False)
    dingtalk_webhook = models.CharField('钉钉Webhook', max_length=512,
                                        blank=True, default='')
    email_enabled = models.BooleanField('邮件推送', default=False)
    email_to = models.CharField('邮件接收人', max_length=512, blank=True, default='')
    email_subject_prefix = models.CharField('邮件主题前缀', max_length=64,
                                            default='[eSight安全告警]')
    updated_at = models.DateTimeField('更新时间', auto_now=True)

    class Meta:
        db_table = 'cmdb_alert_rule'
        verbose_name = '告警规则'
        verbose_name_plural = verbose_name

    def __str__(self):
        return u'AlertRule(thr=%s, win=%dm, every=%dm)' % (
            self.severity_threshold, self.window_minutes, self.scan_interval_minutes)


class AlertEvent(models.Model):
    """告警事件：以 fingerprint 唯一，具备 firing/acked/resolved/suppressed 生命周期。"""
    STATUS_CHOICES = [
        ('firing', '触发中'),
        ('acked', '已确认'),
        ('resolved', '已恢复'),
        ('suppressed', '已忽略'),
    ]
    SOURCE_CHOICES = [
        ('WAF', 'WAF'),
        ('Firewall', '防火墙'),
    ]

    fingerprint = models.CharField('事件指纹', max_length=64, unique=True, db_index=True)
    source = models.CharField('来源', max_length=16, choices=SOURCE_CHOICES, default='WAF')
    event_type = models.CharField('攻击类型', max_length=255, blank=True, default='')
    src_ip = models.CharField('源IP', max_length=64, blank=True, default='', db_index=True)
    dst_ip = models.CharField('目的IP', max_length=64, blank=True, default='')
    severity = models.CharField('严重级别', max_length=32, blank=True, default='')

    status = models.CharField('状态', max_length=16, choices=STATUS_CHOICES,
                              default='firing', db_index=True)
    occurrence = models.IntegerField('累计次数', default=1)
    notify_count = models.IntegerField('已推送次数', default=0)

    first_seen = models.DateTimeField('首次出现', auto_now_add=True)
    last_seen = models.DateTimeField('最后出现', auto_now=True)
    last_notified_at = models.DateTimeField('上次推送', null=True, blank=True)
    resolved_at = models.DateTimeField('恢复时间', null=True, blank=True)

    # 运营字段
    acked_by = models.CharField('确认人', max_length=64, blank=True, default='')
    ack_note = models.TextField('处理备注', blank=True, default='')

    class Meta:
        db_table = 'cmdb_alert_event'
        verbose_name = '告警事件'
        verbose_name_plural = verbose_name
        ordering = ['-last_seen']
        indexes = [
            models.Index(fields=['status', '-last_seen']),
        ]

    def __str__(self):
        return u'%s %s %s->%s x%d [%s]' % (
            self.source, self.event_type[:24], self.src_ip, self.dst_ip,
            self.occurrence, self.status)


class AlertRecord(models.Model):
    """每次扫描的结果快照（审计用）。"""
    scan_time = models.DateTimeField('扫描时间', auto_now_add=True)
    trigger = models.CharField('触发方式', max_length=16, default='manual',
                               help_text='manual=手动 / scheduled=定时')
    window_start = models.DateTimeField('窗口起点', null=True, blank=True)
    window_minutes = models.IntegerField('时间窗', default=60)
    severity_threshold = models.CharField('阈值', max_length=16, default='high')
    waf_new = models.IntegerField('WAF新增高危', default=0)
    fw_new = models.IntegerField('防火墙新增高危', default=0)
    vuln_high = models.IntegerField('系统漏洞高危(现状)', default=0)
    web_high = models.IntegerField('WEB漏洞高危(现状)', default=0)
    total_new = models.IntegerField('攻击新增合计', default=0)

    # 2026-08-28 深化：收敛/生命周期统计
    events_new = models.IntegerField('新增事件', default=0)
    events_recurred = models.IntegerField('复现事件', default=0)
    events_resolved = models.IntegerField('恢复事件', default=0)
    events_suppressed = models.IntegerField('冷却抑制', default=0)

    notified = models.BooleanField('是否推送', default=False)
    channels = models.CharField('通知通道', max_length=64, blank=True, default='')
    detail = models.TextField('明细(JSON)', blank=True, default='')
    error = models.TextField('错误信息', blank=True, default='')

    class Meta:
        db_table = 'cmdb_alert_record'
        verbose_name = '告警记录'
        verbose_name_plural = verbose_name
        ordering = ['-scan_time']

    def __str__(self):
        return u'%s trigger=%s new=%d resolved=%d notified=%s' % (
            self.scan_time, self.trigger, self.events_new, self.events_resolved, self.notified)
