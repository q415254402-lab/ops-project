"""
拓扑管理模型
"""
from django.db import models


class TopologyMap(models.Model):
    """拓扑图"""
    TYPE_CHOICES = [
        ('physical', '物理拓扑'),
        ('logical', '逻辑拓扑'),
        ('vlan', 'VLAN 拓扑'),
        ('custom', '自定义拓扑'),
    ]

    name = models.CharField('拓扑名称', max_length=128)
    map_type = models.CharField('拓扑类型', max_length=16, choices=TYPE_CHOICES)
    description = models.TextField('描述', blank=True, default='')
    layout_config = models.JSONField('布局配置', default=dict, blank=True)
    is_default = models.BooleanField('默认拓扑', default=False)
    created_at = models.DateTimeField('创建时间', auto_now_add=True)
    updated_at = models.DateTimeField('更新时间', auto_now=True)

    class Meta:
        db_table = 'topo_map'
        verbose_name = '拓扑图'
        verbose_name_plural = verbose_name

    def __str__(self):
        return f'{self.name} ({self.get_map_type_display()})'


class TopologyNode(models.Model):
    """拓扑节点"""
    topology_map = models.ForeignKey(
        TopologyMap, on_delete=models.CASCADE,
        related_name='nodes', verbose_name='拓扑图',
    )
    device = models.ForeignKey(
        'cmdb.Device', null=True, blank=True,
        on_delete=models.CASCADE,
        related_name='topology_nodes', verbose_name='设备',
    )
    label = models.CharField('显示名称', max_length=128, blank=True, default='')
    x = models.FloatField('X 坐标', default=0)
    y = models.FloatField('Y 坐标', default=0)
    layer = models.CharField('层级', max_length=32, blank=True, default='')  # core, distribution, access
    icon = models.CharField('图标', max_length=128, blank=True, default='')
    style = models.JSONField('样式', default=dict, blank=True)

    class Meta:
        db_table = 'topo_node'
        verbose_name = '拓扑节点'
        verbose_name_plural = verbose_name


class TopologyLink(models.Model):
    """拓扑连接"""
    topology_map = models.ForeignKey(
        TopologyMap, on_delete=models.CASCADE,
        related_name='links', verbose_name='拓扑图',
    )
    source_node = models.ForeignKey(
        TopologyNode, on_delete=models.CASCADE,
        related_name='outgoing_links', verbose_name='源节点',
    )
    source_interface = models.ForeignKey(
        'cmdb.Interface', null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name='topo_src_links', verbose_name='源接口',
    )
    target_node = models.ForeignKey(
        TopologyNode, on_delete=models.CASCADE,
        related_name='incoming_links', verbose_name='目标节点',
    )
    target_interface = models.ForeignKey(
        'cmdb.Interface', null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name='topo_tgt_links', verbose_name='目标接口',
    )
    link_type = models.CharField('连接类型', max_length=16, default='physical')
    bandwidth = models.BigIntegerField('带宽 (bps)', default=0)
    utilization = models.FloatField('利用率 (%)', default=0)
    status = models.CharField('状态', max_length=16, default='up')
    style = models.JSONField('样式', default=dict, blank=True)

    class Meta:
        db_table = 'topo_link'
        verbose_name = '拓扑连接'
        verbose_name_plural = verbose_name


class DiscoveryTask(models.Model):
    """自动发现任务"""
    STATUS_CHOICES = [
        ('pending', '待执行'),
        ('running', '执行中'),
        ('completed', '已完成'),
        ('failed', '失败'),
    ]

    name = models.CharField('任务名称', max_length=128)
    ip_ranges = models.JSONField('IP 范围', default=list)  # ['192.168.1.0/24', '10.0.0.1-10.0.0.254']
    credentials = models.ManyToManyField(
        'cmdb.Credential', blank=True,
        related_name='discovery_tasks', verbose_name='尝试凭据',
    )
    protocols = models.JSONField('发现协议', default=list)  # ['icmp', 'snmp', 'lldp']
    status = models.CharField('状态', max_length=16, choices=STATUS_CHOICES, default='pending')
    result = models.JSONField('发现结果', default=dict, blank=True)
    discovered_count = models.IntegerField('发现设备数', default=0)
    error_message = models.TextField('错误信息', blank=True, default='')
    scheduled_at = models.DateTimeField('计划时间', null=True, blank=True)
    started_at = models.DateTimeField('开始时间', null=True, blank=True)
    completed_at = models.DateTimeField('完成时间', null=True, blank=True)
    created_at = models.DateTimeField('创建时间', auto_now_add=True)

    class Meta:
        db_table = 'topo_discovery_task'
        verbose_name = '发现任务'
        verbose_name_plural = verbose_name
