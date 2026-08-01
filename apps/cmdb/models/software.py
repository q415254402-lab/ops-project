"""
CMDB 软件资产模型
"""
from django.db import models


class Software(models.Model):
    """软件资产"""
    name = models.CharField('软件名称', max_length=128)
    version = models.CharField('版本', max_length=64, blank=True, default='')
    vendor = models.CharField('厂商', max_length=128, blank=True, default='')
    category = models.CharField('分类', max_length=32, blank=True, default='')  # os, db, middleware, app
    devices = models.ManyToManyField(
        'Device', blank=True,
        related_name='softwares', verbose_name='安装设备',
    )
    description = models.TextField('描述', blank=True, default='')
    created_at = models.DateTimeField('创建时间', auto_now_add=True)

    class Meta:
        db_table = 'cmdb_software'
        verbose_name = '软件'
        verbose_name_plural = verbose_name

    def __str__(self):
        return f'{self.name} {self.version}'


class License(models.Model):
    """License 管理"""
    STATUS_CHOICES = [
        ('active', '有效'),
        ('expired', '已过期'),
        ('expiring_soon', '即将过期'),
    ]

    software = models.ForeignKey(
        Software, on_delete=models.CASCADE,
        related_name='licenses', verbose_name='软件',
    )
    license_key = models.TextField('License Key')
    license_type = models.CharField('授权类型', max_length=32, blank=True, default='')
    max_instances = models.IntegerField('最大实例数', default=1)
    current_instances = models.IntegerField('当前实例数', default=0)
    issued_at = models.DateField('签发日期', null=True, blank=True)
    expires_at = models.DateField('到期日期', null=True, blank=True)
    status = models.CharField('状态', max_length=16, choices=STATUS_CHOICES, default='active')
    description = models.TextField('描述', blank=True, default='')

    class Meta:
        db_table = 'cmdb_license'
        verbose_name = 'License'
        verbose_name_plural = verbose_name

    def __str__(self):
        return f'{self.software.name} License'
