"""
告警管理模型 — 告警定义、实时告警、历史告警、Trap/Syslog 规则
"""
from django.db import models


class AlarmDefinition(models.Model):
    """告警定义"""
    SEVERITY_CHOICES = [
        ('critical', '紧急'),
        ('major', '重要'),
        ('minor', '次要'),
        ('warning', '提示'),
        ('info', '信息'),
    ]
    SOURCE_CHOICES = [
        ('trap', 'SNMP Trap'),
        ('syslog', 'Syslog'),
        ('polling', '主动轮询'),
        ('threshold', '阈值触发'),
        ('script', '脚本检测'),
    ]

    name = models.CharField('告警名称', max_length=128)
    code = models.CharField('告警编码', max_length=64, unique=True)
    severity = models.CharField('严重等级', max_length=16, choices=SEVERITY_CHOICES)
    source = models.CharField('告警来源', max_length=16, choices=SOURCE_CHOICES)
    description = models.TextField('描述', blank=True, default='')
    # 匹配规则 (JSON)
    match_rules = models.JSONField('匹配规则', default=dict, blank=True)
    # 自动清除
    auto_clear = models.BooleanField('自动清除', default=True)
    clear_rules = models.JSONField('清除规则', default=dict, blank=True)
    # 通知
    notify_enabled = models.BooleanField('启用通知', default=True)
    notify_channels = models.JSONField('通知渠道', default=list, blank=True)  # ['email', 'webhook', 'wechat']
    notify_contacts = models.JSONField('通知对象', default=list, blank=True)
    # 压缩
    compress_window = models.IntegerField('压缩窗口 (秒)', default=300)
    # 状态
    enabled = models.BooleanField('启用', default=True)
    created_at = models.DateTimeField('创建时间', auto_now_add=True)
    updated_at = models.DateTimeField('更新时间', auto_now=True)

    class Meta:
        db_table = 'alarm_definition'
        verbose_name = '告警定义'
        verbose_name_plural = verbose_name
        ordering = ['-severity', 'name']

    def __str__(self):
        return f'{self.name} [{self.get_severity_display()}]'


class Alarm(models.Model):
    """实时告警"""
    STATUS_CHOICES = [
        ('active', '活跃'),
        ('acknowledged', '已确认'),
        ('cleared', '已清除'),
    ]
    SEVERITY_CHOICES = AlarmDefinition.SEVERITY_CHOICES

    alarm_definition = models.ForeignKey(
        AlarmDefinition, null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name='alarms', verbose_name='告警定义',
    )
    device = models.ForeignKey(
        'cmdb.Device', null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name='alarms', verbose_name='关联设备',
    )
    interface = models.ForeignKey(
        'cmdb.Interface', null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name='alarms', verbose_name='关联接口',
    )
    severity = models.CharField('严重等级', max_length=16, choices=SEVERITY_CHOICES)
    status = models.CharField('状态', max_length=16, choices=STATUS_CHOICES, default='active')
    title = models.CharField('告警标题', max_length=256)
    detail = models.TextField('告警详情', blank=True, default='')
    # 原始数据
    raw_data = models.JSONField('原始数据', default=dict, blank=True)
    source_ip = models.GenericIPAddressField('来源 IP', null=True, blank=True)
    # 关联 & 压缩
    parent_alarm = models.ForeignKey(
        'self', null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name='child_alarms', verbose_name='父告警',
    )
    occurrence_count = models.IntegerField('发生次数', default=1)
    is_root_cause = models.BooleanField('是否根因', default=False)
    # 时间
    first_occurred_at = models.DateTimeField('首次发生时间')
    last_occurred_at = models.DateTimeField('最后发生时间')
    acknowledged_by = models.CharField('确认人', max_length=64, blank=True, default='')
    acknowledged_at = models.DateTimeField('确认时间', null=True, blank=True)
    cleared_by = models.CharField('清除方式', max_length=64, blank=True, default='')
    cleared_at = models.DateTimeField('清除时间', null=True, blank=True)
    created_at = models.DateTimeField('创建时间', auto_now_add=True)

    class Meta:
        db_table = 'alarm'
        verbose_name = '实时告警'
        verbose_name_plural = verbose_name
        ordering = ['-last_occurred_at']
        indexes = [
            models.Index(fields=['status', 'severity'], name='idx_alarm_status_severity'),
            models.Index(fields=['device', 'status'], name='idx_alarm_device_status'),
            models.Index(fields=['-last_occurred_at'], name='idx_alarm_time'),
        ]

    def __str__(self):
        return f'[{self.get_severity_display()}] {self.title}'


class AlarmHistory(models.Model):
    """历史告警（归档）"""
    alarm_id = models.BigIntegerField('原始告警 ID')
    alarm_definition_code = models.CharField('告警编码', max_length=64, blank=True, default='')
    device_ip = models.GenericIPAddressField('设备 IP', null=True, blank=True)
    device_name = models.CharField('设备名称', max_length=128, blank=True, default='')
    severity = models.CharField('严重等级', max_length=16)
    title = models.CharField('告警标题', max_length=256)
    detail = models.TextField('详情', blank=True, default='')
    occurrence_count = models.IntegerField('发生次数', default=1)
    first_occurred_at = models.DateTimeField('首次发生时间')
    last_occurred_at = models.DateTimeField('最后发生时间')
    cleared_at = models.DateTimeField('清除时间', null=True, blank=True)
    archived_at = models.DateTimeField('归档时间', auto_now_add=True)

    class Meta:
        db_table = 'alarm_history'
        verbose_name = '历史告警'
        verbose_name_plural = verbose_name
        ordering = ['-archived_at']
        indexes = [
            models.Index(fields=['-first_occurred_at'], name='idx_alarmhist_time'),
            models.Index(fields=['device_ip'], name='idx_alarmhist_ip'),
        ]


class SyslogRule(models.Model):
    """Syslog 解析规则"""
    name = models.CharField('规则名称', max_length=64)
    vendor = models.CharField('厂商', max_length=32, blank=True, default='')
    pattern = models.TextField('匹配模式 (正则)')
    severity_mapping = models.JSONField('等级映射', default=dict, blank=True)
    alarm_definition = models.ForeignKey(
        AlarmDefinition, null=True, blank=True,
        on_delete=models.SET_NULL,
        verbose_name='关联告警定义',
    )
    enabled = models.BooleanField('启用', default=True)
    created_at = models.DateTimeField('创建时间', auto_now_add=True)

    class Meta:
        db_table = 'alarm_syslog_rule'
        verbose_name = 'Syslog 规则'
        verbose_name_plural = verbose_name


class TrapRule(models.Model):
    """SNMP Trap 解析规则"""
    name = models.CharField('规则名称', max_length=64)
    oid = models.CharField('Trap OID', max_length=128)
    vendor = models.CharField('厂商', max_length=32, blank=True, default='')
    severity = models.CharField('严重等级', max_length=16, default='warning')
    title_template = models.CharField('标题模板', max_length=256, blank=True, default='')
    detail_template = models.TextField('详情模板', blank=True, default='')
    alarm_definition = models.ForeignKey(
        AlarmDefinition, null=True, blank=True,
        on_delete=models.SET_NULL,
        verbose_name='关联告警定义',
    )
    enabled = models.BooleanField('启用', default=True)
    created_at = models.DateTimeField('创建时间', auto_now_add=True)

    class Meta:
        db_table = 'alarm_trap_rule'
        verbose_name = 'Trap 规则'
        verbose_name_plural = verbose_name


class AlarmNotificationLog(models.Model):
    """告警通知日志"""
    alarm = models.ForeignKey(
        Alarm, on_delete=models.CASCADE,
        related_name='notification_logs', verbose_name='告警',
    )
    channel = models.CharField('通知渠道', max_length=32)  # email, webhook, wechat
    recipient = models.CharField('接收人', max_length=256)
    status = models.CharField('发送状态', max_length=16)  # success, failed
    error_message = models.TextField('错误信息', blank=True, default='')
    sent_at = models.DateTimeField('发送时间', auto_now_add=True)

    class Meta:
        db_table = 'alarm_notification_log'
        verbose_name = '通知日志'
        verbose_name_plural = verbose_name
