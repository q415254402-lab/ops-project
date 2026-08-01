"""
CMDB 网络模型 — VLAN、IP 地址、MAC 地址
"""
from django.db import models


class Vlan(models.Model):
    """VLAN"""
    vlan_id = models.IntegerField('VLAN ID', unique=True)
    name = models.CharField('VLAN 名称', max_length=64)
    description = models.TextField('描述', blank=True, default='')
    devices = models.ManyToManyField(
        'Device', blank=True,
        related_name='vlans', verbose_name='关联设备',
    )
    created_at = models.DateTimeField('创建时间', auto_now_add=True)

    class Meta:
        db_table = 'cmdb_vlan'
        verbose_name = 'VLAN'
        verbose_name_plural = verbose_name
        ordering = ['vlan_id']

    def __str__(self):
        return f'VLAN {self.vlan_id} - {self.name}'


class IPAddress(models.Model):
    """IP 地址管理"""
    STATUS_CHOICES = [
        ('available', '可用'),
        ('allocated', '已分配'),
        ('reserved', '保留'),
        ('conflict', '冲突'),
    ]

    address = models.GenericIPAddressField('IP 地址', unique=True)
    subnet = models.CharField('子网', max_length=18)  # e.g. 192.168.1.0/24
    gateway = models.GenericIPAddressField('网关', null=True, blank=True)
    vlan = models.ForeignKey(
        Vlan, null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name='ip_addresses', verbose_name='VLAN',
    )
    device = models.ForeignKey(
        'Device', null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name='ip_addresses', verbose_name='关联设备',
    )
    interface = models.ForeignKey(
        'Interface', null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name='ip_addresses', verbose_name='关联接口',
    )
    status = models.CharField('状态', max_length=16, choices=STATUS_CHOICES, default='available')
    hostname = models.CharField('主机名', max_length=128, blank=True, default='')
    description = models.CharField('描述', max_length=256, blank=True, default='')
    last_seen_at = models.DateTimeField('最后发现时间', null=True, blank=True)
    created_at = models.DateTimeField('创建时间', auto_now_add=True)
    updated_at = models.DateTimeField('更新时间', auto_now=True)

    class Meta:
        db_table = 'cmdb_ip_address'
        verbose_name = 'IP 地址'
        verbose_name_plural = verbose_name
        ordering = ['address']
        indexes = [
            models.Index(fields=['subnet'], name='idx_ip_subnet'),
            models.Index(fields=['status'], name='idx_ip_status'),
        ]

    def __str__(self):
        return f'{self.address} ({self.get_status_display()})'


class MacAddress(models.Model):
    """MAC 地址表"""
    mac = models.CharField('MAC 地址', max_length=17)
    device = models.ForeignKey(
        'Device', on_delete=models.CASCADE,
        related_name='mac_addresses', verbose_name='设备',
    )
    interface = models.ForeignKey(
        'Interface', null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name='mac_addresses', verbose_name='接口',
    )
    vlan_id = models.IntegerField('VLAN ID', null=True, blank=True)
    type = models.CharField('类型', max_length=16, default='dynamic')  # dynamic/static
    ip_address = models.GenericIPAddressField('IP 地址', null=True, blank=True)
    last_seen_at = models.DateTimeField('最后发现时间', null=True, blank=True)

    class Meta:
        db_table = 'cmdb_mac_address'
        verbose_name = 'MAC 地址'
        verbose_name_plural = verbose_name
        indexes = [
            models.Index(fields=['mac'], name='idx_mac_addr'),
        ]

    def __str__(self):
        return self.mac
