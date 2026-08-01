"""
CMDB 服务器模型
"""
from django.db import models


class Server(models.Model):
    """服务器扩展信息（与 Device 一对一）"""
    device = models.OneToOneField(
        'Device', on_delete=models.CASCADE,
        related_name='server_detail', verbose_name='关联设备',
    )
    cpu_model = models.CharField('CPU 型号', max_length=128, blank=True, default='')
    cpu_cores = models.IntegerField('CPU 核数', default=0)
    memory_total_gb = models.FloatField('内存总量 (GB)', default=0)
    disk_total_gb = models.FloatField('磁盘总量 (GB)', default=0)
    os_name = models.CharField('操作系统', max_length=64, blank=True, default='')
    os_version = models.CharField('OS 版本', max_length=64, blank=True, default='')
    kernel_version = models.CharField('内核版本', max_length=64, blank=True, default='')
    uptime_days = models.IntegerField('运行天数', default=0)
    is_virtual = models.BooleanField('是否虚拟机', default=False)
    hypervisor = models.CharField('虚拟化平台', max_length=64, blank=True, default='')

    class Meta:
        db_table = 'cmdb_server'
        verbose_name = '服务器'
        verbose_name_plural = verbose_name

    def __str__(self):
        return f'Server: {self.device.name}'


class CPUMetric(models.Model):
    """CPU 使用率快照"""
    device = models.ForeignKey('Device', on_delete=models.CASCADE, related_name='cpu_metrics')
    usage_percent = models.FloatField('CPU 使用率 (%)')
    load_1 = models.FloatField('1 分钟负载', default=0)
    load_5 = models.FloatField('5 分钟负载', default=0)
    load_15 = models.FloatField('15 分钟负载', default=0)
    timestamp = models.DateTimeField('采集时间', db_index=True)

    class Meta:
        db_table = 'cmdb_cpu_metric'
        verbose_name = 'CPU 指标'
        verbose_name_plural = verbose_name


class MemoryMetric(models.Model):
    """内存使用率快照"""
    device = models.ForeignKey('Device', on_delete=models.CASCADE, related_name='memory_metrics')
    total_mb = models.BigIntegerField('总内存 (MB)', default=0)
    used_mb = models.BigIntegerField('已用内存 (MB)', default=0)
    usage_percent = models.FloatField('内存使用率 (%)')
    timestamp = models.DateTimeField('采集时间', db_index=True)

    class Meta:
        db_table = 'cmdb_memory_metric'
        verbose_name = '内存指标'
        verbose_name_plural = verbose_name


class DiskMetric(models.Model):
    """磁盘使用率快照"""
    device = models.ForeignKey('Device', on_delete=models.CASCADE, related_name='disk_metrics')
    mount_point = models.CharField('挂载点', max_length=128)
    total_gb = models.FloatField('总量 (GB)', default=0)
    used_gb = models.FloatField('已用 (GB)', default=0)
    usage_percent = models.FloatField('使用率 (%)')
    timestamp = models.DateTimeField('采集时间', db_index=True)

    class Meta:
        db_table = 'cmdb_disk_metric'
        verbose_name = '磁盘指标'
        verbose_name_plural = verbose_name
