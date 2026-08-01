"""
CMDB 基础模型 — 厂商、凭据
"""
from django.db import models
from django_cryptography.fields import encrypt


class Manufacturer(models.Model):
    """设备厂商"""
    name = models.CharField('厂商名称', max_length=128, unique=True)
    code = models.CharField('厂商编码', max_length=32, unique=True)
    website = models.URLField('官网', blank=True, default='')
    description = models.TextField('描述', blank=True, default='')
    created_at = models.DateTimeField('创建时间', auto_now_add=True)
    updated_at = models.DateTimeField('更新时间', auto_now=True)

    class Meta:
        db_table = 'cmdb_manufacturer'
        verbose_name = '厂商'
        verbose_name_plural = verbose_name
        ordering = ['name']

    def __str__(self):
        return self.name


class Credential(models.Model):
    """设备认证凭据（加密存储）"""
    PROTOCOL_CHOICES = [
        ('snmp_v1', 'SNMPv1'),
        ('snmp_v2c', 'SNMPv2c'),
        ('snmp_v3', 'SNMPv3'),
        ('ssh', 'SSH'),
        ('telnet', 'Telnet'),
        ('wmi', 'WMI'),
        ('ipmi', 'IPMI'),
        ('api', 'RESTful API'),
    ]

    name = models.CharField('凭据名称', max_length=64)
    protocol = models.CharField('协议', max_length=16, choices=PROTOCOL_CHOICES)
    username = models.CharField('用户名', max_length=64, blank=True, default='')
    password = encrypt(models.CharField('密码', max_length=256, blank=True, default=''))
    community = models.CharField('SNMP Community', max_length=64, blank=True, default='')
    snmp_version = models.CharField('SNMP 版本', max_length=8, blank=True, default='')
    snmp_security_level = models.CharField('安全级别', max_length=32, blank=True, default='')
    ssh_key = encrypt(models.TextField('SSH 私钥', blank=True, default=''))
    ssh_port = models.IntegerField('SSH 端口', default=22)
    extra_params = models.JSONField('附加参数', default=dict, blank=True)
    description = models.TextField('描述', blank=True, default='')
    created_at = models.DateTimeField('创建时间', auto_now_add=True)
    updated_at = models.DateTimeField('更新时间', auto_now=True)

    class Meta:
        db_table = 'cmdb_credential'
        verbose_name = '设备凭据'
        verbose_name_plural = verbose_name

    def __str__(self):
        return f'{self.name} ({self.get_protocol_display()})'
