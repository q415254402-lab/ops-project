"""
系统管理模型 — 审计日志、系统参数、数据字典
"""
from django.db import models


class OperationLog(models.Model):
    """操作审计日志"""
    ACTION_CHOICES = [
        ('create', '创建'),
        ('update', '更新'),
        ('delete', '删除'),
        ('login', '登录'),
        ('logout', '登出'),
        ('export', '导出'),
        ('import', '导入'),
        ('execute', '执行'),
    ]

    user = models.CharField('操作人', max_length=64)
    action = models.CharField('操作类型', max_length=16, choices=ACTION_CHOICES)
    resource_type = models.CharField('资源类型', max_length=64)
    resource_id = models.CharField('资源 ID', max_length=64, blank=True, default='')
    resource_name = models.CharField('资源名称', max_length=256, blank=True, default='')
    detail = models.TextField('操作详情', blank=True, default='')
    ip_address = models.GenericIPAddressField('操作 IP')
    user_agent = models.CharField('User Agent', max_length=512, blank=True, default='')
    result = models.CharField('操作结果', max_length=16, default='success')  # success, failed
    created_at = models.DateTimeField('操作时间', auto_now_add=True, db_index=True)

    class Meta:
        db_table = 'sys_operation_log'
        verbose_name = '操作日志'
        verbose_name_plural = verbose_name
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', '-created_at'], name='idx_audit_user_time'),
            models.Index(fields=['resource_type'], name='idx_audit_resource'),
        ]


class SystemParameter(models.Model):
    """系统参数"""
    CATEGORY_CHOICES = [
        ('general', '基本设置'),
        ('notification', '通知设置'),
        ('collection', '采集设置'),
        ('alarm', '告警设置'),
        ('security', '安全设置'),
    ]

    category = models.CharField('分类', max_length=16, choices=CATEGORY_CHOICES)
    key = models.CharField('参数键', max_length=64, unique=True)
    value = models.TextField('参数值')
    value_type = models.CharField('值类型', max_length=16, default='string')  # string, int, bool, json
    description = models.CharField('描述', max_length=256, blank=True, default='')
    updated_at = models.DateTimeField('更新时间', auto_now=True)

    class Meta:
        db_table = 'sys_parameter'
        verbose_name = '系统参数'
        verbose_name_plural = verbose_name

    def __str__(self):
        return f'{self.key} = {self.value}'


class DataDict(models.Model):
    """数据字典"""
    type_code = models.CharField('字典类型编码', max_length=32)
    type_name = models.CharField('字典类型名称', max_length=64)
    item_code = models.CharField('字典项编码', max_length=32)
    item_name = models.CharField('字典项名称', max_length=64)
    sort_order = models.IntegerField('排序', default=0)
    enabled = models.BooleanField('启用', default=True)
    extra = models.JSONField('扩展属性', default=dict, blank=True)

    class Meta:
        db_table = 'sys_data_dict'
        verbose_name = '数据字典'
        verbose_name_plural = verbose_name
        unique_together = ('type_code', 'item_code')
        ordering = ['type_code', 'sort_order']
