# -*- coding: utf-8 -*-
"""
eSight IP 地址管理模型（复刻 OpsAny control ip_manager 模块）
- 字段命名/类型与 control IpSubnetManagerGroupModel/IpSubnetManagerModel/IpAddressModel/IpManagerScanLogModel 一致
- 数据本地落库（v2 路线，与网络设备模块一致）
- 表名加 esight_ 前缀避开与 control 冲突
"""
from django.db import models

from apps.cmdb.models.control_models import BaseModel, ControllerAdmin


class IpSubnetManagerGroupModel(BaseModel):
    """IP 管理分组（树，多级父子）"""
    name = models.CharField('分组名', max_length=150)
    parent = models.ForeignKey('self', null=True, blank=True,
                               on_delete=models.CASCADE,
                               related_name='ip_manager_group_parent',
                               verbose_name='父分组')

    class Meta:
        db_table = 'esight_ip_subnet_manager_group'
        verbose_name = 'IP管理分组'
        verbose_name_plural = verbose_name

    def to_base_dict(self):
        return {'id': self.id, 'name': self.name}

    def to_dict(self):
        return {'id': self.id, 'name': self.name, 'parent_id': self.parent_id}

    def to_parent_dict(self):
        """递归 children + count（本组+子孙组子网数），对齐 control"""
        children = []
        for i in IpSubnetManagerGroupModel.objects.filter(parent=self).order_by('create_time'):
            children.append(i.to_parent_dict())
        count = IpSubnetManagerModel.objects.filter(
            ip_manager_group__in=self.get_children_group_queryset()).count()
        return {
            'id': self.id, 'name': self.name,
            'parent_id': self.parent_id,
            'children': children,
            'count': count,
        }

    def get_children_group_queryset(self):
        """递归收集 self + 所有子孙分组（对齐 control）"""
        children_group_queryset = [self]
        query_set = IpSubnetManagerGroupModel.objects.filter(parent=self)
        children_group_queryset.extend(query_set)
        for children_query in query_set:
            children_query_set = IpSubnetManagerGroupModel.objects.filter(parent=children_query)
            children_group_queryset.extend(children_query_set)
            if children_query_set:
                children_group_queryset += children_query.get_children_group_queryset()
        return list(set(children_group_queryset))


class IpSubnetManagerModel(BaseModel):
    """IPv4 子网"""
    name = models.CharField('子网名称', max_length=150)
    description = models.CharField('描述', max_length=255, null=True, blank=True)
    subnet_addr = models.CharField('子网地址', max_length=150)
    subnet_mask = models.CharField('子网掩码', max_length=150)
    timeout = models.IntegerField('超时时间', default=300)
    add_type = models.CharField('添加方式', max_length=50, default='')
    vlan_name = models.CharField('VLAN名称', max_length=150, null=True, blank=True)
    location = models.CharField('位置', max_length=150, null=True, blank=True)
    controller = models.ForeignKey(ControllerAdmin, null=True, blank=True,
                                   on_delete=models.SET_NULL,
                                   related_name='controller_ip_subnet', verbose_name='控制器')
    ip_manager_group = models.ForeignKey(IpSubnetManagerGroupModel,
                                         on_delete=models.CASCADE,
                                         related_name='ip_group_manager',
                                         verbose_name='IP管理分组')
    scan_status = models.CharField('扫描状态', max_length=50, default='not_scan')
    scan_message = models.CharField('扫描信息', max_length=255, null=True, blank=True)
    last_scan_time = models.DateTimeField(null=True, blank=True)
    last_scan_start_timestamp = models.CharField(max_length=20, null=True, blank=True)
    last_scan_start_str = models.CharField(max_length=50, null=True, blank=True)
    last_scan_end_timestamp = models.CharField(max_length=20, null=True, blank=True)
    last_scan_end_str = models.CharField(max_length=50, null=True, blank=True)
    elapsed = models.CharField(max_length=20, null=True, blank=True)
    ip_total_count = models.IntegerField('总数', default=0)
    ip_used_count = models.IntegerField('已用数量', default=0)
    ip_available_count = models.IntegerField('可用数量', default=0)
    ip_transient_count = models.IntegerField('瞬态数量', default=0)
    ip_not_scanned_count = models.IntegerField('未扫描', default=0)

    class Meta:
        db_table = 'esight_ip_subnet_manager'
        verbose_name = 'IP子网'
        verbose_name_plural = verbose_name

    def to_base_dict(self):
        return {'id': self.id, 'name': self.name, 'description': self.description}

    def to_dict(self):
        dt = {
            'id': self.id, 'name': self.name, 'description': self.description,
            'subnet_addr': self.subnet_addr, 'subnet_mask': self.subnet_mask,
            'vlan_name': self.vlan_name, 'timeout': self.timeout,
            'location': self.location, 'scan_status': self.scan_status,
            'scan_message': self.scan_message, 'last_scan_time': self.last_scan_time,
            'add_type': self.add_type,
            'ip_total_count': self.ip_total_count,
            'ip_used_count': self.ip_used_count,
            'ip_available_count': self.ip_available_count,
            'ip_transient_count': self.ip_transient_count,
            'ip_not_scanned_count': self.ip_not_scanned_count,
            'usage_rate': 0,
        }
        if self.ip_manager_group_id:
            dt['ip_manager'] = self.ip_manager_group.to_base_dict()
        if self.controller_id:
            dt['controller'] = {'id': self.controller.id, 'name': self.controller.name,
                                'proxy_status': self.controller.proxy_status,
                                'proxy_public_status': self.controller.proxy_public_status}
        if isinstance(self.ip_used_count, int) and isinstance(self.ip_total_count, int):
            if self.ip_used_count > 0 and self.ip_total_count > 0:
                dt['usage_rate'] = round(self.ip_used_count / self.ip_total_count * 100, 2)
        return dt


class IpAddressModel(BaseModel):
    """IP 地址（扫描落库，不手工增删）"""
    ip_address = models.CharField('IP地址', max_length=150)
    host_name = models.TextField('主机名', default='')
    ip_type = models.CharField('IP地址类型', max_length=150, null=True, blank=True)
    mac_address = models.CharField('MAC地址', max_length=150, null=True, blank=True)
    mac_addr_type = models.CharField('MAC地址类型', max_length=50, null=True, blank=True)
    vendor = models.CharField('供应商', max_length=150, null=True, blank=True)
    state = models.CharField('状态', max_length=50, default='unknown')
    state_reason = models.CharField('原因', max_length=50, null=True, blank=True)
    state_reason_ttl = models.CharField('state_reason_ttl', max_length=50, null=True, blank=True)
    ip_manager = models.ForeignKey(IpSubnetManagerModel,
                                   on_delete=models.CASCADE,
                                   related_name='ip_manager_address',
                                   verbose_name='IP管理')

    class Meta:
        db_table = 'esight_ip_address'
        verbose_name = 'IP地址'
        verbose_name_plural = verbose_name

    def to_base_dict(self):
        return {'id': self.id, 'ip_address': self.ip_address, 'state': self.state}

    def to_overview_dict(self):
        return {'ip_address': self.ip_address, 'state': self.state}

    def to_status_dict(self):
        return {'id': self.id, 'ip_address': self.ip_address, 'state': self.state}

    def to_dict(self):
        return {
            'id': self.id, 'ip_address': self.ip_address, 'host_name': self.host_name,
            'mac_address': self.mac_address, 'mac_addr_type': self.mac_addr_type,
            'vendor': self.vendor, 'state': self.state,
            'state_reason': self.state_reason, 'state_reason_ttl': self.state_reason_ttl,
        }

    def to_detail_dict(self):
        dt = self.to_dict()
        if self.ip_manager_id:
            dt['ip_manager'] = self.ip_manager.to_base_dict()
        return dt


class IpManagerScanLogModel(BaseModel):
    """子网扫描日志"""
    ip_manager = models.ForeignKey(IpSubnetManagerModel,
                                   on_delete=models.CASCADE,
                                   related_name='ip_manager_scan_log',
                                   verbose_name='IP管理')
    request_id = models.CharField('request_id', max_length=50, null=True, blank=True)
    subnet_addr = models.CharField('子网地址', max_length=50)
    initial_data = models.TextField('原始扫描结果', null=True, blank=True)
    scan_type = models.CharField('扫描类型', max_length=50, default='ip')
    scan_message = models.CharField('扫描信息', max_length=255, null=True, blank=True)

    class Meta:
        db_table = 'esight_ip_manager_scan_log'
        verbose_name = 'IP扫描日志'
        verbose_name_plural = verbose_name

    def to_base_dict(self):
        dt = {'id': self.id, 'subnet_addr': self.subnet_addr, 'initial_data': self.initial_data}
        if self.ip_manager_id:
            dt['ip_manager'] = self.ip_manager.to_base_dict()
        return dt
