"""
CMDB 设备模型 — 设备类型、型号、设备主表、接口
"""
from django.db import models


class DeviceType(models.Model):
    """设备类型"""
    name = models.CharField('类型名称', max_length=64, unique=True)
    code = models.CharField('类型编码', max_length=32, unique=True)
    icon = models.CharField('图标', max_length=128, blank=True, default='')
    parent = models.ForeignKey(
        'self', null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name='children',
        verbose_name='父类型',
    )
    sort_order = models.IntegerField('排序', default=0)
    created_at = models.DateTimeField('创建时间', auto_now_add=True)

    class Meta:
        db_table = 'cmdb_device_type'
        verbose_name = '设备类型'
        verbose_name_plural = verbose_name
        ordering = ['sort_order', 'name']

    def __str__(self):
        return self.name


class DeviceModel(models.Model):
    """设备型号"""
    manufacturer = models.ForeignKey(
        'Manufacturer', on_delete=models.CASCADE,
        related_name='device_models', verbose_name='厂商',
    )
    name = models.CharField('型号名称', max_length=128)
    device_type = models.ForeignKey(
        DeviceType, on_delete=models.CASCADE,
        related_name='device_models', verbose_name='设备类型',
    )
    snmp_sysobjectid = models.CharField('SNMP SysObjectID', max_length=128, blank=True, default='')
    description = models.TextField('描述', blank=True, default='')
    created_at = models.DateTimeField('创建时间', auto_now_add=True)

    class Meta:
        db_table = 'cmdb_device_model'
        verbose_name = '设备型号'
        verbose_name_plural = verbose_name
        unique_together = ('manufacturer', 'name')

    def __str__(self):
        return f'{self.manufacturer.name} {self.name}'


class Device(models.Model):
    """设备主表"""
    STATUS_CHOICES = [
        ('online', '在线'),
        ('offline', '离线'),
        ('maintenance', '维护中'),
        ('decommissioned', '已退役'),
    ]
    MANAGE_CHOICES = [
        ('auto', '自动管理'),
        ('manual', '手工管理'),
    ]

    # 基本信息
    name = models.CharField('设备名称', max_length=128)
    hostname = models.CharField('主机名', max_length=128, blank=True, default='')
    ip_address = models.GenericIPAddressField('管理 IP', unique=True)
    mac_address = models.CharField('MAC 地址', max_length=17, blank=True, default='')
    # 分类
    device_type = models.ForeignKey(
        DeviceType, on_delete=models.PROTECT,
        related_name='devices', verbose_name='设备类型',
    )
    device_model = models.ForeignKey(
        DeviceModel, null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name='devices', verbose_name='设备型号',
    )
    manufacturer = models.ForeignKey(
        'Manufacturer', null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name='devices', verbose_name='厂商',
    )
    # 硬件信息
    serial_number = models.CharField('序列号', max_length=128, blank=True, default='')
    firmware_version = models.CharField('固件版本', max_length=64, blank=True, default='')
    os_version = models.CharField('OS 版本', max_length=64, blank=True, default='')
    # 状态
    status = models.CharField('状态', max_length=20, choices=STATUS_CHOICES, default='offline')
    manage_type = models.CharField('管理方式', max_length=10, choices=MANAGE_CHOICES, default='auto')
    # 位置
    room = models.ForeignKey(
        'cmdb.Room', null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name='devices', verbose_name='机房',
    )
    cabinet = models.ForeignKey(
        'cmdb.Cabinet', null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name='devices', verbose_name='机柜',
    )
    cabinet_position = models.IntegerField('U 位', null=True, blank=True)
    # 采集凭据
    credential = models.ForeignKey(
        'Credential', null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name='devices', verbose_name='设备凭据',
    )
    # 扩展
    tags = models.JSONField('标签', default=list, blank=True)
    description = models.TextField('描述', blank=True, default='')
    # 时间
    discovered_at = models.DateTimeField('发现时间', null=True, blank=True)
    last_sync_at = models.DateTimeField('最后同步时间', null=True, blank=True)
    last_seen_at = models.DateTimeField('最后在线时间', null=True, blank=True)
    created_at = models.DateTimeField('创建时间', auto_now_add=True)
    updated_at = models.DateTimeField('更新时间', auto_now=True)

    class Meta:
        db_table = 'cmdb_device'
        verbose_name = '设备'
        verbose_name_plural = verbose_name
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['ip_address'], name='idx_device_ip'),
            models.Index(fields=['status'], name='idx_device_status'),
            models.Index(fields=['device_type'], name='idx_device_type'),
        ]

    def __str__(self):
        return f'{self.name} ({self.ip_address})'


class Interface(models.Model):
    """网络接口"""
    STATUS_CHOICES = [
        ('up', '启用'),
        ('down', '禁用'),
        ('unknown', '未知'),
    ]
    TYPE_CHOICES = [
        ('physical', '物理接口'),
        ('virtual', '虚拟接口'),
        ('loopback', 'Loopback'),
        ('vlan', 'VLAN 接口'),
        ('tunnel', '隧道'),
    ]

    device = models.ForeignKey(
        Device, on_delete=models.CASCADE,
        related_name='interfaces', verbose_name='所属设备',
    )
    name = models.CharField('接口名称', max_length=128)
    index = models.IntegerField('接口索引', default=0)
    description = models.CharField('接口描述', max_length=256, blank=True, default='')
    if_type = models.CharField('接口类型', max_length=16, choices=TYPE_CHOICES, default='physical')
    status = models.CharField('状态', max_length=16, choices=STATUS_CHOICES, default='unknown')
    admin_status = models.BooleanField('管理状态', default=True)
    mac_address = models.CharField('MAC 地址', max_length=17, blank=True, default='')
    ip_address = models.GenericIPAddressField('IP 地址', null=True, blank=True)
    mask = models.CharField('子网掩码', max_length=15, blank=True, default='')
    speed = models.BigIntegerField('速率 (bps)', default=0)
    duplex = models.CharField('双工模式', max_length=16, blank=True, default='')
    vlan_id = models.IntegerField('VLAN ID', null=True, blank=True)
    # 流量统计 (最后一次采集)
    in_octets = models.BigIntegerField('入方向字节', default=0)
    out_octets = models.BigIntegerField('出方向字节', default=0)
    in_errors = models.BigIntegerField('入方向错误', default=0)
    out_errors = models.BigIntegerField('出方向错误', default=0)
    in_discards = models.BigIntegerField('入方向丢包', default=0)
    out_discards = models.BigIntegerField('出方向丢包', default=0)
    # LLDP 邻居
    lldp_remote_device = models.CharField('LLDP 远端设备', max_length=128, blank=True, default='')
    lldp_remote_port = models.CharField('LLDP 远端端口', max_length=128, blank=True, default='')
    last_sync_at = models.DateTimeField('最后同步时间', null=True, blank=True)

    class Meta:
        db_table = 'cmdb_interface'
        verbose_name = '网络接口'
        verbose_name_plural = verbose_name
        unique_together = ('device', 'name')
        indexes = [
            models.Index(fields=['device', 'status'], name='idx_iface_dev_status'),
        ]

    def __str__(self):
        return f'{self.device.name} - {self.name}'
