"""
网络管理模型 — SLA 探测、NetFlow 分析
"""
from django.db import models


class SLAProbe(models.Model):
    """SLA 探测任务"""
    TYPE_CHOICES = [
        ('icmp', 'ICMP Ping'),
        ('tcp', 'TCP Connect'),
        ('dns', 'DNS Query'),
        ('http', 'HTTP GET'),
    ]

    name = models.CharField('探测名称', max_length=128)
    probe_type = models.CharField('探测类型', max_length=8, choices=TYPE_CHOICES)
    source_device = models.ForeignKey(
        'cmdb.Device', on_delete=models.CASCADE,
        related_name='sla_probes', verbose_name='源设备',
    )
    target_ip = models.GenericIPAddressField('目标 IP')
    target_port = models.IntegerField('目标端口', null=True, blank=True)
    target_url = models.URLField('目标 URL', blank=True, default='')
    interval = models.IntegerField('探测间隔 (秒)', default=60)
    timeout = models.IntegerField('超时 (秒)', default=5)
    # SLA 阈值
    rtt_threshold_ms = models.FloatField('RTT 阈值 (ms)', default=100)
    loss_threshold_percent = models.FloatField('丢包率阈值 (%)', default=5)
    enabled = models.BooleanField('启用', default=True)
    created_at = models.DateTimeField('创建时间', auto_now_add=True)

    class Meta:
        db_table = 'net_sla_probe'
        verbose_name = 'SLA 探测'
        verbose_name_plural = verbose_name


class SLAData(models.Model):
    """SLA 探测数据"""
    probe = models.ForeignKey(
        SLAProbe, on_delete=models.CASCADE,
        related_name='data', verbose_name='探测任务',
    )
    rtt_ms = models.FloatField('RTT (ms)', default=0)
    loss_percent = models.FloatField('丢包率 (%)', default=0)
    jitter_ms = models.FloatField('抖动 (ms)', default=0)
    is_reachable = models.BooleanField('是否可达', default=True)
    timestamp = models.DateTimeField('探测时间', db_index=True)

    class Meta:
        db_table = 'net_sla_data'
        verbose_name = 'SLA 数据'
        verbose_name_plural = verbose_name
        indexes = [
            models.Index(fields=['probe', 'timestamp'], name='idx_sla_probe_time'),
        ]


class NetflowRecord(models.Model):
    """NetFlow/sFlow 记录"""
    source_ip = models.GenericIPAddressField('源 IP')
    dest_ip = models.GenericIPAddressField('目的 IP')
    source_port = models.IntegerField('源端口')
    dest_port = models.IntegerField('目的端口')
    protocol = models.IntegerField('协议号')
    bytes_count = models.BigIntegerField('字节数')
    packets_count = models.BigIntegerField('包数')
    first_seen = models.DateTimeField('首次出现')
    last_seen = models.DateTimeField('最后出现')
    input_interface = models.IntegerField('入接口索引', null=True, blank=True)
    output_interface = models.IntegerField('出接口索引', null=True, blank=True)
    device = models.ForeignKey(
        'cmdb.Device', null=True, blank=True,
        on_delete=models.SET_NULL, verbose_name='采集设备',
    )
    timestamp = models.DateTimeField('记录时间', db_index=True)

    class Meta:
        db_table = 'net_netflow_record'
        verbose_name = 'NetFlow 记录'
        verbose_name_plural = verbose_name
        indexes = [
            models.Index(fields=['source_ip', 'timestamp'], name='idx_netflow_src_time'),
            models.Index(fields=['dest_ip', 'timestamp'], name='idx_netflow_dst_time'),
        ]
