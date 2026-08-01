"""
性能管理模型 — 指标定义、采集任务、阈值、性能数据
"""
from django.db import models


class MetricDefinition(models.Model):
    """指标定义"""
    AGGREGATION_CHOICES = [
        ('avg', '平均值'),
        ('max', '最大值'),
        ('min', '最小值'),
        ('sum', '求和'),
        ('last', '最新值'),
    ]
    COLLECTION_CHOICES = [
        ('snmp', 'SNMP'),
        ('ssh', 'SSH'),
        ('wmi', 'WMI'),
        ('ipmi', 'IPMI'),
        ('ping', 'Ping'),
        ('script', '自定义脚本'),
    ]

    name = models.CharField('指标名称', max_length=64)
    code = models.CharField('指标编码', max_length=64, unique=True)
    unit = models.CharField('单位', max_length=16, blank=True, default='')  # %, bps, count, ms
    device_type = models.ForeignKey(
        'cmdb.DeviceType', on_delete=models.CASCADE,
        related_name='metrics', verbose_name='设备类型',
    )
    collection_method = models.CharField('采集方式', max_length=16, choices=COLLECTION_CHOICES)
    # SNMP 采集参数
    oid = models.CharField('OID', max_length=128, blank=True, default='')
    snmp_type = models.CharField('SNMP 数据类型', max_length=16, blank=True, default='gauge32')
    # SSH 采集参数
    command = models.CharField('SSH 命令', max_length=256, blank=True, default='')
    parse_regex = models.CharField('解析正则', max_length=256, blank=True, default='')
    # 脚本采集
    script = models.TextField('采集脚本', blank=True, default='')
    # 聚合 & 保留
    aggregation = models.CharField('聚合方式', max_length=8, choices=AGGREGATION_CHOICES, default='avg')
    retention_days = models.IntegerField('保留天数', default=90)
    # 状态
    enabled = models.BooleanField('启用', default=True)
    description = models.TextField('描述', blank=True, default='')
    created_at = models.DateTimeField('创建时间', auto_now_add=True)

    class Meta:
        db_table = 'perf_metric_definition'
        verbose_name = '指标定义'
        verbose_name_plural = verbose_name

    def __str__(self):
        return f'{self.name} ({self.code})'


class CollectTask(models.Model):
    """采集任务"""
    STATUS_CHOICES = [
        ('running', '运行中'),
        ('stopped', '已停止'),
        ('error', '异常'),
    ]

    name = models.CharField('任务名称', max_length=128)
    devices = models.ManyToManyField(
        'cmdb.Device', blank=True,
        related_name='collect_tasks', verbose_name='采集设备',
    )
    device_groups = models.JSONField('设备分组', default=list, blank=True)
    metrics = models.ManyToManyField(
        MetricDefinition,
        related_name='collect_tasks', verbose_name='采集指标',
    )
    interval = models.IntegerField('采集间隔 (秒)', default=300)
    status = models.CharField('状态', max_length=16, choices=STATUS_CHOICES, default='stopped')
    enabled = models.BooleanField('启用', default=True)
    last_run_at = models.DateTimeField('最后运行时间', null=True, blank=True)
    last_error = models.TextField('最后错误', blank=True, default='')
    created_at = models.DateTimeField('创建时间', auto_now_add=True)
    updated_at = models.DateTimeField('更新时间', auto_now=True)

    class Meta:
        db_table = 'perf_collect_task'
        verbose_name = '采集任务'
        verbose_name_plural = verbose_name

    def __str__(self):
        return self.name


class MetricThreshold(models.Model):
    """阈值配置"""
    LEVEL_CHOICES = [
        ('warning', '提示'),
        ('minor', '次要'),
        ('major', '重要'),
        ('critical', '紧急'),
    ]

    metric = models.ForeignKey(
        MetricDefinition, on_delete=models.CASCADE,
        related_name='thresholds', verbose_name='指标',
    )
    device = models.ForeignKey(
        'cmdb.Device', null=True, blank=True,
        on_delete=models.CASCADE,
        related_name='thresholds', verbose_name='设备 (空=全局)',
    )
    level = models.CharField('阈值等级', max_length=16, choices=LEVEL_CHOICES)
    min_value = models.FloatField('下限值', null=True, blank=True)
    max_value = models.FloatField('上限值', null=True, blank=True)
    consecutive_count = models.IntegerField('连续次数', default=1)
    enabled = models.BooleanField('启用', default=True)
    created_at = models.DateTimeField('创建时间', auto_now_add=True)

    class Meta:
        db_table = 'perf_metric_threshold'
        verbose_name = '阈值配置'
        verbose_name_plural = verbose_name
        unique_together = ('metric', 'device', 'level')


class MetricData(models.Model):
    """性能数据（MySQL 存储，大规模建议用 InfluxDB）"""
    device = models.ForeignKey(
        'cmdb.Device', on_delete=models.CASCADE,
        related_name='metric_data', verbose_name='设备',
    )
    metric = models.ForeignKey(
        MetricDefinition, on_delete=models.CASCADE,
        related_name='data', verbose_name='指标',
    )
    value = models.FloatField('值')
    timestamp = models.DateTimeField('采集时间', db_index=True)

    class Meta:
        db_table = 'perf_metric_data'
        verbose_name = '性能数据'
        verbose_name_plural = verbose_name
        indexes = [
            models.Index(fields=['device', 'metric', 'timestamp'], name='idx_metric_dev_time'),
        ]


class InterfaceTraffic(models.Model):
    """接口流量数据（独立表，高频写入）"""
    device = models.ForeignKey('cmdb.Device', on_delete=models.CASCADE)
    interface = models.ForeignKey('cmdb.Interface', on_delete=models.CASCADE)
    in_octets = models.BigIntegerField('入方向字节', default=0)
    out_octets = models.BigIntegerField('出方向字节', default=0)
    in_bps = models.FloatField('入方向速率 (bps)', default=0)
    out_bps = models.FloatField('出方向速率 (bps)', default=0)
    in_utilization = models.FloatField('入方向利用率 (%)', default=0)
    out_utilization = models.FloatField('出方向利用率 (%)', default=0)
    in_errors = models.BigIntegerField('入方向错误', default=0)
    out_errors = models.BigIntegerField('出方向错误', default=0)
    in_discards = models.BigIntegerField('入方向丢包', default=0)
    out_discards = models.BigIntegerField('出方向丢包', default=0)
    timestamp = models.DateTimeField('采集时间', db_index=True)

    class Meta:
        db_table = 'perf_interface_traffic'
        verbose_name = '接口流量'
        verbose_name_plural = verbose_name
        indexes = [
            models.Index(fields=['interface', 'timestamp'], name='idx_traffic_if_time'),
        ]
