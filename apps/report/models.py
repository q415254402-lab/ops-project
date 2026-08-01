"""
报表中心模型
"""
from django.db import models


class ReportTemplate(models.Model):
    """报表模板"""
    TYPE_CHOICES = [
        ('asset', '资产报表'),
        ('alarm', '告警报表'),
        ('performance', '性能报表'),
        ('compliance', '合规报表'),
        ('custom', '自定义报表'),
    ]
    FORMAT_CHOICES = [
        ('pdf', 'PDF'),
        ('excel', 'Excel'),
        ('html', 'HTML'),
    ]

    name = models.CharField('报表名称', max_length=128)
    report_type = models.CharField('报表类型', max_length=16, choices=TYPE_CHOICES)
    description = models.TextField('描述', blank=True, default='')
    # 报表配置 (JSON 定义数据源、图表、表格等)
    config = models.JSONField('报表配置', default=dict)
    # 定时生成
    schedule_enabled = models.BooleanField('定时生成', default=False)
    schedule_cron = models.CharField('Cron 表达式', max_length=64, blank=True, default='')
    output_format = models.CharField('输出格式', max_length=8, choices=FORMAT_CHOICES, default='pdf')
    # 通知
    notify_email = models.TextField('接收邮箱', blank=True, default='')  # 逗号分隔
    created_by = models.CharField('创建人', max_length=64)
    created_at = models.DateTimeField('创建时间', auto_now_add=True)
    updated_at = models.DateTimeField('更新时间', auto_now=True)

    class Meta:
        db_table = 'rpt_template'
        verbose_name = '报表模板'
        verbose_name_plural = verbose_name


class ReportInstance(models.Model):
    """报表实例（已生成的报表）"""
    STATUS_CHOICES = [
        ('generating', '生成中'),
        ('completed', '已完成'),
        ('failed', '失败'),
    ]

    template = models.ForeignKey(
        ReportTemplate, on_delete=models.CASCADE,
        related_name='instances', verbose_name='报表模板',
    )
    title = models.CharField('报表标题', max_length=256)
    status = models.CharField('状态', max_length=16, choices=STATUS_CHOICES, default='generating')
    file_path = models.CharField('文件路径', max_length=512, blank=True, default='')
    file_size = models.IntegerField('文件大小 (bytes)', default=0)
    parameters = models.JSONField('生成参数', default=dict, blank=True)
    error_message = models.TextField('错误信息', blank=True, default='')
    generated_by = models.CharField('生成人', max_length=64)
    generated_at = models.DateTimeField('生成时间', auto_now_add=True)

    class Meta:
        db_table = 'rpt_instance'
        verbose_name = '报表实例'
        verbose_name_plural = verbose_name
        ordering = ['-generated_at']
