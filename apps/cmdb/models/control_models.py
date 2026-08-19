# -*- coding: utf-8 -*-
"""
eSight 网络设备模型（完全复刻 OpsAny control 网络设备模块）
- 字段命名/类型与 control NetworkEquipmentModel/NetworkGroupModel/ControllerAdmin 等一致
- 数据本地落库（不再代理平台）
- 表名加 esight_ 前缀避开与 control 冲突
"""
from django.db import models


class BaseModel(models.Model):
    """基类"""
    create_time = models.DateTimeField('创建时间', auto_now_add=True, null=True)
    update_time = models.DateTimeField('更新时间', auto_now=True, null=True)

    class Meta:
        abstract = True


class ControllerAdmin(BaseModel):
    """控制器（Proxy/Agent）—— 复刻 control.ControllerAdmin"""
    name = models.CharField('名称', max_length=200)
    ip = models.CharField('IP', max_length=128, blank=True, default='')
    type = models.CharField('类型', max_length=50, blank=True, default='')
    state1 = models.BooleanField('可用', default=True)
    state2 = models.BooleanField('公有可用', default=True)
    count = models.IntegerField('设备数', default=0)
    proxy_url = models.CharField('代理URL', max_length=255, blank=True, default='')
    proxy_public_url = models.CharField('公有URL', max_length=255, blank=True, default='')
    proxy_status = models.BooleanField('代理状态', default=True)
    proxy_public_status = models.BooleanField('公有状态', default=True)
    proxy_description = models.TextField('代理描述', blank=True, default='')
    proxy_agent_count = models.IntegerField('代理Agent数', default=0)
    proxy_token = models.CharField('代理Token', max_length=255, blank=True, default='')
    access_token = models.CharField('访问Token', max_length=255, blank=True, default='')
    api_username = models.CharField('API用户', max_length=100, blank=True, default='')
    api_password = models.CharField('API密码', max_length=255, blank=True, default='')
    extend_fields = models.TextField('扩展字段', blank=True, default='')
    # 2026-08-13 新增：执行模式。'agent'=调平台 opsany-paas-proxy（默认，兼容现状）；
    # 'local'=eSight 进程内直连设备（netmiko + pysnmp，单应用交付，推荐正式环境）。
    exec_mode = models.CharField('执行模式', max_length=20, blank=True, default='',
                                 choices=[('', '远程代理(agent)'), ('agent', '远程代理(agent)'),
                                          ('local', '本地直连(local)')])

    class Meta:
        db_table = 'esight_controller_admin'
        verbose_name = '控制器'
        verbose_name_plural = verbose_name

    def to_proxy_api_dict(self):
        return {
            'url': self.proxy_url,
            'public_url': self.proxy_public_url,
            'proxy_status': self.proxy_status,
            'proxy_public_status': self.proxy_public_status,
            'access_token': self.access_token or self.proxy_token,
            'api_username': self.api_username,
            'api_password': self.api_password,
        }

    def to_dict(self):
        return {
            'id': self.id, 'name': self.name, 'type': self.type,
            'state1': self.state1, 'state2': self.state2, 'count': self.count,
            'proxy_url': self.proxy_url, 'proxy_public_url': self.proxy_public_url,
            'proxy_status': self.proxy_status, 'proxy_public_status': self.proxy_public_status,
            'proxy_description': self.proxy_description,
            'proxy_agent_count': self.proxy_agent_count,
        }


class NetworkGroupModel(BaseModel):
    """网络设备分组 —— 复刻 control.NetworkGroupModel"""
    name = models.CharField('分组名', max_length=100)
    parent = models.ForeignKey('self', null=True, blank=True,
                               on_delete=models.SET_NULL,
                               related_name='children', verbose_name='父分组')
    self_count = models.IntegerField('自身设备数', default=0)
    creator = models.CharField('创建人', max_length=100, blank=True, default='')
    description = models.TextField('描述', blank=True, default='')

    class Meta:
        db_table = 'esight_network_group'
        verbose_name = '网络设备分组'
        verbose_name_plural = verbose_name

    def to_dict(self):
        return {
            'id': self.id, 'name': self.name,
            'parent_id': self.parent_id if self.parent_id else None,
            'self_count': self.self_count, 'creator': self.creator,
            'description': self.description, 'count': self.self_count,
            'children': [],
        }

    def get_children_group_queryset(self):
        """递归收集 self + 所有子孙分组（对齐 control NetworkGroupModel.get_children_group_queryset）"""
        children_group_queryset = [self]
        query_set = NetworkGroupModel.objects.filter(parent=self)
        children_group_queryset.extend(query_set)
        for children_query in query_set:
            children_query_set = NetworkGroupModel.objects.filter(parent=children_query)
            children_group_queryset.extend(children_query_set)
            if children_query_set:
                children_group_queryset += children_query.get_children_group_queryset()
        return list(set(children_group_queryset))

    def get_super_group_name(self):
        """从根到当前组的路径拼接（对齐 control，用于同步 agent 的 network_group 字段）"""
        names = []
        node = self
        while node:
            names.insert(0, node.name)
            node = node.parent
        return '/'.join(names)

    def to_parent_auth_dict_v2(self, network_count_func=None):
        """分组树结构（对齐 control to_parent_auth_dict_v2）：
        {id, name, parent_id, self_count, count, children}"""
        from apps.cmdb.models.control_models import NetworkEquipmentModel
        children = []
        for i in NetworkGroupModel.objects.filter(parent=self).order_by('create_time'):
            children.append(i.to_parent_auth_dict_v2())
        children_ids = [g.id for g in self.get_children_group_queryset()]
        self_count = NetworkEquipmentModel.objects.filter(network_group=self).exclude(controller__isnull=True).count()
        count = NetworkEquipmentModel.objects.filter(network_group_id__in=children_ids).exclude(controller__isnull=True).count()
        return {
            'id': self.id, 'name': self.name, 'parent_id': self.parent_id,
            'self_count': self_count, 'count': count, 'children': children,
        }


class EquipmentTypeCMDBModel(BaseModel):
    """设备类型（CMDB）—— 复刻 control.EquipmentTypeCMDBModel"""
    code = models.CharField('类型编码', max_length=50, unique=True)
    name = models.CharField('类型名称', max_length=100)
    built_in = models.BooleanField('内置', default=False)
    islet = models.BooleanField('独立', default=False)

    class Meta:
        db_table = 'esight_equipment_type'
        verbose_name = '设备类型'
        verbose_name_plural = verbose_name

    def to_dict(self):
        return {
            'id': self.id, 'code': self.code, 'name': self.name,
            'built_in': self.built_in, 'islet': self.islet,
        }


class NetworkEquipmentModel(BaseModel):
    """网络设备主表 —— 复刻 control.NetworkEquipmentModel
    字段顺序/类型与 control NetworkEquipmentBaseForm + NetworkEquipmentForm + state 字段保持一致
    """
    STATE_CHOICES = (
        ('0', 'Never Connect'),
        ('1', 'Normal'),
        ('2', 'Error'),
    )

    name = models.CharField('名称', max_length=100)
    host = models.CharField('唯一标识', max_length=100, unique=True)
    ip = models.CharField('IP', max_length=80, blank=True, default='')
    equipment_type = models.ForeignKey(
        EquipmentTypeCMDBModel, null=True, blank=True,
        on_delete=models.SET_NULL, verbose_name='设备类型',
        related_name='equipments',
    )
    network_group = models.ForeignKey(
        NetworkGroupModel, null=True, blank=True,
        on_delete=models.SET_NULL, verbose_name='所属分组',
        related_name='equipments',
    )
    controller = models.ForeignKey(
        ControllerAdmin, null=True, blank=True,
        on_delete=models.SET_NULL, verbose_name='控制器',
        related_name='equipments',
    )
    device_type = models.CharField('设备型号', max_length=50, blank=True, default='')
    description = models.CharField('描述', max_length=512, blank=True, default='')
    add_type = models.CharField('添加方式', max_length=100, default='1')

    # SNMP
    snmp_version = models.CharField('SNMP版本', max_length=50, blank=True, default='v2c')
    community_name = models.CharField('团体名', max_length=255, blank=True, default='')
    snmp_port = models.CharField('SNMP端口', max_length=50, blank=True, default='161')
    snmp_state = models.CharField('SNMP状态', max_length=10, choices=STATE_CHOICES, default='0')
    snmp_state_message = models.CharField('SNMP状态描述', max_length=255, blank=True, default='Never connect')
    snmp_ping = models.TextField('SNMP探测结果', blank=True, default='')

    # SNMP v3
    context_name = models.CharField('上下文', max_length=512, blank=True, default='')
    security_name = models.CharField('安全名', max_length=512, blank=True, default='')
    security_level = models.CharField('安全级别', max_length=50, blank=True, default='noAuthNoPriv')
    verification_protocol = models.CharField('验证协议', max_length=50, blank=True, default='MD5')
    verify_password = models.CharField('验证密码', max_length=512, blank=True, default='')
    privacy_protocol = models.CharField('加密协议', max_length=50, blank=True, default='DES')
    private_key = models.CharField('加密密码', max_length=512, blank=True, default='')

    # SSH/Telnet 纳管
    connection_type = models.CharField('纳管方式', max_length=50, blank=True, default='')
    login_username = models.CharField('登录用户', max_length=255, blank=True, default='')
    login_password = models.CharField('登录密码', max_length=512, blank=True, default='')
    login_privilege_password = models.CharField('特权密码', max_length=512, blank=True, default='')
    ssh_port = models.CharField('SSH端口', max_length=50, blank=True, default='22')
    ssh_timeout = models.IntegerField('SSH超时', default=5)
    ssh_state = models.CharField('SSH状态', max_length=10, choices=STATE_CHOICES, default='0')
    ssh_state_message = models.CharField('SSH状态描述', max_length=255, blank=True, default='Never connect')
    ssh_ping = models.TextField('SSH探测结果', blank=True, default='')
    telnet_port = models.CharField('Telnet端口', max_length=50, blank=True, default='23')
    telnet_state = models.CharField('Telnet状态', max_length=10, choices=STATE_CHOICES, default='0')
    telnet_state_message = models.CharField('Telnet状态描述', max_length=255, blank=True, default='Never connect')
    telnet_ping = models.TextField('Telnet探测结果', blank=True, default='')

    # 通用
    timeout = models.IntegerField('超时(秒)', default=5)
    telnet_timeout = models.IntegerField('Telnet超时(秒)', default=5)
    api_timeout = models.IntegerField('API超时(秒)', default=5)
    monitor_type = models.CharField('监控方式', max_length=50, blank=True, default='')
    is_bastion = models.BooleanField('堡垒机', default=False)
    is_bastion_cred_create = models.BooleanField('堡垒机凭证创建', default=True)
    creator = models.CharField('创建人', max_length=100, blank=True, default='')
    # 对齐 control 生产表 NOT NULL 字段
    cpu_utilization_rate = models.CharField('CPU使用率', max_length=255, default='0')
    memory_utilization_rate = models.CharField('内存使用率', max_length=255, default='0')
    problem_count = models.IntegerField('问题数', default=0)
    zabbix_host_id = models.CharField('Zabbix主机ID', max_length=50, blank=True, default='')
    zabbix_status = models.CharField('Zabbix状态', max_length=50, blank=True, default='')
    # 管控平台对应设备 id（eSight 本地设备同步创建到管控平台后记录，测试复用管控平台 proxy agent）
    platform_id = models.IntegerField('管控平台设备ID', null=True, blank=True)

    class Meta:
        db_table = 'esight_network_equipment'
        verbose_name = '网络设备'
        verbose_name_plural = verbose_name
        ordering = ['-id']

    def to_dict(self):
        # FK 字段必须返回 dict（含空 id 占位），前端 show() 会做
        #   t.data.network_group = t.data.network_group.id + ""  /  t.data.equipment_type.id + ""
        # 如果 FK 为 None 会抛 TypeError，整段 show then 回调中断 → formData 全空、编辑回填失败。
        eq_type = self.equipment_type.to_dict() if self.equipment_type else {'id': '', 'code': '', 'name': ''}
        grp = self.network_group.to_dict() if self.network_group else {'id': '', 'name': '', 'parent_id': None}
        ctrl = self.controller.to_dict() if self.controller else {'id': '', 'name': ''}
        return {
            'id': self.id, 'name': self.name, 'host': self.host, 'ip': self.ip,
            'device_type': self.device_type,
            'equipment_type': eq_type,
            'network_group': grp,
            'controller_id': self.controller_id,
            'controller': ctrl,
            # SNMP
            'snmp_version': self.snmp_version, 'community_name': self.community_name,
            'snmp_port': self.snmp_port,
            'snmp_state': self.snmp_state, 'snmp_state_message': self.snmp_state_message,
            'snmp_ping': self.snmp_ping,
            # SNMP v3
            'context_name': self.context_name, 'security_name': self.security_name,
            'security_level': self.security_level,
            'verification_protocol': self.verification_protocol, 'verify_password': self.verify_password,
            'privacy_protocol': self.privacy_protocol, 'private_key': self.private_key,
            # SSH/Telnet 纳管
            'connection_type': self.connection_type,
            'login_username': self.login_username,
            'login_password': self.login_password,
            'login_privilege_password': self.login_privilege_password,
            'ssh_port': self.ssh_port, 'telnet_port': self.telnet_port,
            'ssh_timeout': self.ssh_timeout, 'telnet_timeout': self.telnet_timeout,
            'api_timeout': self.api_timeout,
            'timeout': self.timeout,
            'ssh_state': self.ssh_state, 'ssh_state_message': self.ssh_state_message,
            'telnet_state': self.telnet_state, 'telnet_state_message': self.telnet_state_message,
            'ssh_ping': self.ssh_ping, 'telnet_ping': self.telnet_ping,
            # 监控/通用
            'monitor_type': self.monitor_type,
            'is_bastion': self.is_bastion,
            'add_type': self.add_type,
            'description': self.description,
            # 模板/备份/大屏 前端期望 dict 形态，缺失占位（避免 .id 报错）
            'zabbix_template': [], 'template_list': [],
            'backup': None, 'grafana_dashboard': None, 'controller_zabbix': None,
        }

    def to_list_dict(self):
        """列表接口返回的精简格式 — 去掉敏感字段（明文密码/私钥）防泄露
        详情接口（to_dict 完整版 + 单独 ****** 占位）只在 GET ?id=N 单台时返回。"""
        d = self.to_dict()
        # 列表里也置占位，避免任何潜在泄露
        for k in ('login_password', 'login_privilege_password', 'verify_password', 'private_key'):
            d[k] = '******' if d.get(k) else ''
        return d


class NetworkBackupGroupModel(BaseModel):
    """备份策略分组 —— 复刻 control"""
    name = models.CharField('分组名', max_length=100)
    parent = models.ForeignKey('self', null=True, blank=True,
                               on_delete=models.SET_NULL,
                               related_name='children', verbose_name='父分组')
    creator = models.CharField('创建人', max_length=100, blank=True, default='')

    class Meta:
        db_table = 'esight_network_backup_group'
        verbose_name = '备份策略分组'
        verbose_name_plural = verbose_name

    def to_dict(self):
        return {'id': self.id, 'name': self.name, 'parent_id': self.parent_id}


class NetworkBackupModel(BaseModel):
    """备份策略 —— 复刻 control"""
    name = models.CharField('策略名', max_length=100)
    group = models.ForeignKey(NetworkBackupGroupModel, null=True, blank=True,
                              on_delete=models.SET_NULL,
                              related_name='backups', verbose_name='分组')
    backup_type = models.CharField('备份方式', max_length=50, blank=True, default='')
    cron = models.CharField('cron 表达式', max_length=100, blank=True, default='')
    save_count = models.IntegerField('保留份数', default=7)
    description = models.TextField('描述', blank=True, default='')

    class Meta:
        db_table = 'esight_network_backup'
        verbose_name = '备份策略'
        verbose_name_plural = verbose_name


class NetworkBackupTaskModel(BaseModel):
    """备份任务实例 —— 复刻 control"""
    task_name = models.CharField('任务名', max_length=100, unique=True)
    equipment = models.ForeignKey(NetworkEquipmentModel, null=True, blank=True,
                                  on_delete=models.SET_NULL,
                                  related_name='tasks', verbose_name='设备')
    backup = models.ForeignKey(NetworkBackupModel, null=True, blank=True,
                               on_delete=models.SET_NULL,
                               related_name='tasks', verbose_name='策略')
    state = models.CharField('状态', max_length=20, default='pending')
    result = models.TextField('结果', blank=True, default='')

    class Meta:
        db_table = 'esight_network_backup_task'
        verbose_name = '备份任务'
        verbose_name_plural = verbose_name


class NetworkEquipmentLogModel(BaseModel):
    """设备操作日志 —— 复刻 control NetworkEquipmentLog"""
    equipment = models.ForeignKey(NetworkEquipmentModel, null=True, blank=True,
                                  on_delete=models.SET_NULL,
                                  related_name='logs', verbose_name='设备')
    action = models.CharField('操作', max_length=50)
    detail = models.TextField('详情', blank=True, default='')
    user = models.CharField('操作用户', max_length=100, blank=True, default='')
    duration = models.IntegerField('耗时(ms)', default=0)

    class Meta:
        db_table = 'esight_network_equipment_log'
        verbose_name = '设备操作日志'
        verbose_name_plural = verbose_name


class NetworkConfigModel(BaseModel):
    """设备配置（启动/运行）—— 复刻 control.network_config（NetworkConfigModel）
    详情页"配置对比" tab 数据源：boot_config_content=启动配置 / running_config_content=运行配置
    """
    network = models.ForeignKey(NetworkEquipmentModel, null=True, blank=True,
                                on_delete=models.CASCADE,
                                related_name='network_config', verbose_name='设备')
    boot_task_type = models.CharField('启动配置执行类型', max_length=50, default='1')
    boot_start_time = models.DateTimeField('启动开始时间', null=True, blank=True)
    boot_end_time = models.DateTimeField('启动结束时间', null=True, blank=True)
    boot_config_script = models.TextField('启动配置脚本', blank=True, default='')
    boot_config_content = models.TextField('启动配置内容', blank=True, default='')
    boot_username = models.CharField('启动配置执行人', max_length=512, blank=True, default='')
    run_task_type = models.CharField('运行配置执行类型', max_length=50, default='1')
    run_start_time = models.DateTimeField('运行开始时间', null=True, blank=True)
    run_end_time = models.DateTimeField('运行结束时间', null=True, blank=True)
    running_config_script = models.TextField('运行配置脚本', blank=True, default='')
    running_config_content = models.TextField('运行配置内容', blank=True, default='')
    run_username = models.CharField('运行配置执行人', max_length=512, blank=True, default='')

    class Meta:
        db_table = 'esight_network_config'
        verbose_name = '设备配置'
        verbose_name_plural = verbose_name

    def to_diff_config(self):
        return {
            'boot_task_type': self.boot_task_type or '',
            'boot_config_content': self.boot_config_content or '',
            'boot_username': self.boot_username or '',
            'run_task_type': self.run_task_type or '',
            'running_config_content': self.running_config_content or '',
            'run_username': self.run_username or '',
        }


class NetworkSnmpInfoModel(BaseModel):
    """网络设备系统/CPU/内存信息 —— 复刻 control.network_system_basic_info（NetworkSnmpInfoModel）"""
    network = models.ForeignKey(NetworkEquipmentModel, null=True, blank=True,
                                on_delete=models.CASCADE, related_name='snmp_info', verbose_name='设备')
    sys_name = models.CharField('系统名', max_length=200, blank=True, default='')
    sys_services = models.CharField('服务', max_length=200, blank=True, default='')
    sys_location = models.CharField('位置', max_length=200, blank=True, default='')
    sys_contact = models.CharField('联系人', max_length=200, blank=True, default='')
    sys_descr = models.CharField('描述', max_length=200, blank=True, default='')
    sys_up_time = models.CharField('运行时长', max_length=200, blank=True, default='')
    sys_object_id = models.CharField('OID', max_length=200, blank=True, default='')
    snmp_engine_time = models.CharField('引擎时间', max_length=200, blank=True, default='')
    app_version = models.CharField('应用版本', max_length=200, blank=True, default='')
    hardware_version = models.CharField('硬件版本', max_length=200, blank=True, default='')
    ss_cpu_idle = models.CharField('CPU空闲', max_length=200, blank=True, default='')
    monitor_way = models.CharField('监控方式', max_length=200, blank=True, default='')
    cpu_1m = models.CharField('CPU 1分钟', max_length=200, blank=True, default='')
    cpu_5m = models.CharField('CPU 5分钟', max_length=200, blank=True, default='')
    cpu_5s = models.CharField('CPU 5秒', max_length=200, blank=True, default='')
    mem_total_free = models.CharField('内存空闲', max_length=200, blank=True, default='')
    mem_total_real = models.CharField('内存总量', max_length=200, blank=True, default='')
    sys_up_datetime = models.CharField('启动时间', max_length=200, blank=True, default='')
    total_memory = models.CharField('总内存', max_length=200, blank=True, default='')
    total_used = models.CharField('已用内存', max_length=200, blank=True, default='')
    used_rate = models.CharField('使用率', max_length=200, blank=True, default='')
    cpu_ratio = models.CharField('CPU比率', max_length=200, blank=True, default='')
    memory_ratio = models.CharField('内存比率', max_length=200, blank=True, default='')
    physical_descr = models.CharField('物理描述', max_length=200, blank=True, default='')
    physical_mfg_name = models.CharField('厂商', max_length=200, blank=True, default='')
    physical_model_name = models.CharField('型号', max_length=200, blank=True, default='')
    physical_name = models.CharField('物理名', max_length=200, blank=True, default='')
    physical_serial_num = models.CharField('序列号', max_length=200, blank=True, default='')
    physical_software_rev = models.CharField('软件版本', max_length=200, blank=True, default='')
    sys_log = models.TextField('系统日志', blank=True, default='')
    sys_version = models.CharField('系统版本', max_length=200, blank=True, default='')

    class Meta:
        db_table = 'esight_network_snmp_info'
        verbose_name = '网络设备系统信息'
        verbose_name_plural = verbose_name


class NetworkInterfaceInfoModel(BaseModel):
    """网络设备接口信息 —— 复刻 control.network_interface"""
    network = models.ForeignKey(NetworkEquipmentModel, null=True, blank=True,
                                on_delete=models.CASCADE, related_name='interfaces', verbose_name='设备')
    if_index = models.IntegerField('接口索引', null=True, blank=True)
    if_name = models.CharField('接口名', max_length=255, blank=True, default='')
    if_descr = models.CharField('接口描述', max_length=255, blank=True, default='')
    if_type = models.CharField('接口类型', max_length=100, blank=True, default='')
    if_phys_address = models.CharField('物理地址', max_length=100, blank=True, default='')
    if_admin_status = models.CharField('管理状态', max_length=100, blank=True, default='')
    if_oper_status = models.CharField('操作状态', max_length=100, blank=True, default='')
    if_speed = models.CharField('速率', max_length=100, blank=True, default='')
    if_alias = models.CharField('别名', max_length=200, blank=True, default='')
    if_in_octets = models.CharField('入流量', max_length=100, blank=True, default='')
    if_out_octets = models.CharField('出流量', max_length=100, blank=True, default='')

    class Meta:
        db_table = 'esight_network_interface'
        verbose_name = '网络设备接口信息'
        verbose_name_plural = verbose_name

    def to_dict(self):
        # if_admin_status/if_oper_status：本地执行器无 MIB 时 snmpwalk 输出数字（1/2），
        # 前端统计/表格按符号匹配（"up(1)"==up、"down(2)"==down、"testing(3)"==testing）——统一转符号。
        return {
            'id': self.id,
            'if_index': self.if_index, 'if_name': self.if_name, 'if_descr': self.if_descr,
            'if_type': self.if_type, 'if_phys_address': self.if_phys_address,
            'if_admin_status': _if_status_symbol(self.if_admin_status),
            'if_oper_status': _if_status_symbol(self.if_oper_status),
            'if_speed': self.if_speed, 'if_alias': self.if_alias,
            'if_in_octets': self.if_in_octets, 'if_out_octets': self.if_out_octets,
        }


def _if_status_symbol(v):
    """IF-MIB 接口状态枚举：数字/裸符号 → 前端期望的符号形式（up(1)/down(2)/testing(3)）。"""
    v = str(v or '')
    if v in ('1', 'up', 'up(1)'):
        return 'up(1)'
    if v in ('2', 'down', 'down(2)'):
        return 'down(2)'
    if v in ('3', 'testing', 'testing(3)'):
        return 'testing(3)'
    return v


class NetworkIpInfoModel(BaseModel):
    """网络设备 IP 信息 —— 复刻 control.network_ip_info"""
    network = models.ForeignKey(NetworkEquipmentModel, null=True, blank=True,
                                on_delete=models.CASCADE, related_name='ip_infos', verbose_name='设备')
    ip_net_to_media_if_index = models.IntegerField('接口索引', null=True, blank=True)
    ip_net_to_media_phys_address = models.CharField('物理地址', max_length=255, blank=True, default='')
    ip_net_to_media_net_address = models.CharField('IP地址', max_length=255, blank=True, default='')
    ip_ad_ent_net_mask = models.CharField('子网掩码', max_length=100, blank=True, default='')
    ip_net_to_media_type = models.CharField('类型', max_length=255, blank=True, default='')

    class Meta:
        db_table = 'esight_network_ip_info'
        verbose_name = '网络设备IP信息'
        verbose_name_plural = verbose_name

    def to_dict(self):
        return {
            'id': self.id,
            'ip_net_to_media_if_index': self.ip_net_to_media_if_index,
            'ip_net_to_media_phys_address': self.ip_net_to_media_phys_address,
            'ip_net_to_media_net_address': self.ip_net_to_media_net_address,
            'ip_ad_ent_net_mask': self.ip_ad_ent_net_mask,
            'ip_net_to_media_type': self.ip_net_to_media_type,
        }
