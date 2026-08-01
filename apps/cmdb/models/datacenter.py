"""
CMDB 机房模型
"""
from django.db import models


class Room(models.Model):
    """机房"""
    name = models.CharField('机房名称', max_length=128, unique=True)
    code = models.CharField('机房编码', max_length=32, unique=True)
    address = models.CharField('地址', max_length=256, blank=True, default='')
    area = models.CharField('区域', max_length=64, blank=True, default='')
    floor = models.CharField('楼层', max_length=32, blank=True, default='')
    contact = models.CharField('联系人', max_length=64, blank=True, default='')
    phone = models.CharField('联系电话', max_length=32, blank=True, default='')
    temperature = models.FloatField('温度 (℃)', null=True, blank=True)
    humidity = models.FloatField('湿度 (%)', null=True, blank=True)
    total_power_kw = models.FloatField('总功率 (kW)', null=True, blank=True)
    description = models.TextField('描述', blank=True, default='')
    created_at = models.DateTimeField('创建时间', auto_now_add=True)

    class Meta:
        db_table = 'cmdb_room'
        verbose_name = '机房'
        verbose_name_plural = verbose_name

    def __str__(self):
        return self.name


class Cabinet(models.Model):
    """机柜"""
    STATUS_CHOICES = [
        ('normal', '正常'),
        ('warning', '告警'),
        ('offline', '离线'),
    ]

    room = models.ForeignKey(
        Room, on_delete=models.CASCADE,
        related_name='cabinets', verbose_name='机房',
    )
    name = models.CharField('机柜名称', max_length=64)
    code = models.CharField('机柜编码', max_length=32)
    total_u = models.IntegerField('总 U 数', default=42)
    used_u = models.IntegerField('已用 U 数', default=0)
    power_capacity_kw = models.FloatField('额定功率 (kW)', default=0)
    current_power_kw = models.FloatField('当前功率 (kW)', default=0)
    status = models.CharField('状态', max_length=16, choices=STATUS_CHOICES, default='normal')
    description = models.TextField('描述', blank=True, default='')
    created_at = models.DateTimeField('创建时间', auto_now_add=True)

    class Meta:
        db_table = 'cmdb_cabinet'
        verbose_name = '机柜'
        verbose_name_plural = verbose_name
        unique_together = ('room', 'code')

    def __str__(self):
        return f'{self.room.name} - {self.name}'


class UPS(models.Model):
    """UPS 不间断电源"""
    name = models.CharField('名称', max_length=128)
    room = models.ForeignKey(Room, on_delete=models.CASCADE, related_name='ups_devices')
    model = models.CharField('型号', max_length=64, blank=True, default='')
    capacity_va = models.IntegerField('容量 (VA)', default=0)
    load_percent = models.FloatField('负载率 (%)', default=0)
    battery_percent = models.FloatField('电池电量 (%)', default=0)
    status = models.CharField('状态', max_length=16, default='normal')
    ip_address = models.GenericIPAddressField('管理 IP', null=True, blank=True)

    class Meta:
        db_table = 'cmdb_ups'
        verbose_name = 'UPS'
        verbose_name_plural = verbose_name

    def __str__(self):
        return self.name


class PDU(models.Model):
    """PDU 电源分配单元"""
    name = models.CharField('名称', max_length=128)
    cabinet = models.ForeignKey(Cabinet, on_delete=models.CASCADE, related_name='pdu_devices')
    model = models.CharField('型号', max_length=64, blank=True, default='')
    outlets = models.IntegerField('插口数', default=0)
    current_a = models.FloatField('当前电流 (A)', default=0)
    max_current_a = models.FloatField('额定电流 (A)', default=0)
    ip_address = models.GenericIPAddressField('管理 IP', null=True, blank=True)

    class Meta:
        db_table = 'cmdb_pdu'
        verbose_name = 'PDU'
        verbose_name_plural = verbose_name

    def __str__(self):
        return self.name
