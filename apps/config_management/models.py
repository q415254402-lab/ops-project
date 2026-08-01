"""
配置管理模型
"""
from django.db import models


class ConfigBackup(models.Model):
    """配置备份记录"""
    device = models.ForeignKey(
        'cmdb.Device', on_delete=models.CASCADE,
        related_name='config_backups', verbose_name='设备',
    )
    config_type = models.CharField('配置类型', max_length=16, default='running')  # running, startup
    content = models.TextField('配置内容')
    checksum = models.CharField('校验和 (MD5)', max_length=64)
    backup_method = models.CharField('备份方式', max_length=16, default='ssh')  # ssh, tftp, snmp
    is_changed = models.BooleanField('是否有变更', default=False)
    diff_content = models.TextField('变更差异', blank=True, default='')
    version = models.IntegerField('版本号')
    created_at = models.DateTimeField('创建时间', auto_now_add=True)

    class Meta:
        db_table = 'cm_config_backup'
        verbose_name = '配置备份'
        verbose_name_plural = verbose_name
        unique_together = ('device', 'version')
        ordering = ['-version']


class ConfigTemplate(models.Model):
    """配置模板 (Jinja2)"""
    name = models.CharField('模板名称', max_length=128)
    device_type = models.ForeignKey(
        'cmdb.DeviceType', on_delete=models.CASCADE,
        related_name='config_templates', verbose_name='设备类型',
    )
    vendor = models.ForeignKey(
        'cmdb.Manufacturer', null=True, blank=True,
        on_delete=models.SET_NULL, verbose_name='厂商',
    )
    template_content = models.TextField('模板内容 (Jinja2)')
    variables = models.JSONField('变量定义', default=dict, blank=True)
    description = models.TextField('描述', blank=True, default='')
    created_at = models.DateTimeField('创建时间', auto_now_add=True)
    updated_at = models.DateTimeField('更新时间', auto_now=True)

    class Meta:
        db_table = 'cm_config_template'
        verbose_name = '配置模板'
        verbose_name_plural = verbose_name


class ComplianceRule(models.Model):
    """合规检查规则"""
    RULE_TYPE_CHOICES = [
        ('regex', '正则匹配'),
        ('keyword', '关键字检查'),
        ('script', '脚本检查'),
        ('absence', '缺失检查'),
    ]

    name = models.CharField('规则名称', max_length=128)
    description = models.TextField('描述', blank=True, default='')
    device_type = models.ForeignKey(
        'cmdb.DeviceType', on_delete=models.CASCADE,
        related_name='compliance_rules', verbose_name='设备类型',
    )
    rule_type = models.CharField('规则类型', max_length=16, choices=RULE_TYPE_CHOICES)
    rule_content = models.TextField('规则内容')
    expected_result = models.JSONField('期望结果', default=dict, blank=True)
    severity = models.CharField('严重等级', max_length=16, default='warning')
    enabled = models.BooleanField('启用', default=True)
    created_at = models.DateTimeField('创建时间', auto_now_add=True)

    class Meta:
        db_table = 'cm_compliance_rule'
        verbose_name = '合规规则'
        verbose_name_plural = verbose_name


class ComplianceCheckResult(models.Model):
    """合规检查结果"""
    rule = models.ForeignKey(
        ComplianceRule, on_delete=models.CASCADE,
        related_name='results', verbose_name='规则',
    )
    device = models.ForeignKey(
        'cmdb.Device', on_delete=models.CASCADE,
        related_name='compliance_results', verbose_name='设备',
    )
    passed = models.BooleanField('是否通过')
    detail = models.TextField('检查详情', blank=True, default='')
    checked_at = models.DateTimeField('检查时间', auto_now_add=True)

    class Meta:
        db_table = 'cm_compliance_result'
        verbose_name = '合规检查结果'
        verbose_name_plural = verbose_name
        ordering = ['-checked_at']


class BatchJob(models.Model):
    """批量配置下发任务"""
    STATUS_CHOICES = [
        ('pending', '待执行'),
        ('running', '执行中'),
        ('completed', '已完成'),
        ('partial', '部分完成'),
        ('failed', '失败'),
    ]

    name = models.CharField('任务名称', max_length=128)
    template = models.ForeignKey(
        ConfigTemplate, on_delete=models.CASCADE,
        verbose_name='配置模板',
    )
    devices = models.ManyToManyField(
        'cmdb.Device',
        related_name='batch_jobs', verbose_name='目标设备',
    )
    variables = models.JSONField('变量值', default=dict, blank=True)
    commands = models.TextField('执行命令', blank=True, default='')
    status = models.CharField('状态', max_length=16, choices=STATUS_CHOICES, default='pending')
    result = models.JSONField('执行结果', default=dict, blank=True)
    success_count = models.IntegerField('成功数', default=0)
    fail_count = models.IntegerField('失败数', default=0)
    created_by = models.CharField('创建人', max_length=64)
    started_at = models.DateTimeField('开始时间', null=True, blank=True)
    completed_at = models.DateTimeField('完成时间', null=True, blank=True)
    created_at = models.DateTimeField('创建时间', auto_now_add=True)

    class Meta:
        db_table = 'cm_batch_job'
        verbose_name = '批量任务'
        verbose_name_plural = verbose_name
