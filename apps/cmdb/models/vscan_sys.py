# -*- coding: utf-8 -*-
"""
系统漏洞（vullogsystem）落库模型（2026-08-26，复用 WEB 漏洞 DB 化模式）
目的：①查询秒开（不再实时拉 vScan 8-20s）②慢速上游移到后台同步（类 WEB 漏洞）

单一当前快照语义：每次同步全量替换（VscanVuln.objects.all().delete() + bulk_create）。
去重在前端同步服务用 (asset_name, ip, name, port) 完成，故本表不设唯一约束，仅建查询索引。
"""
from django.db import models


class VscanVuln(models.Model):
    """系统漏洞（vScan vullogsystem queryplugin 全量去重落库）"""
    asset_group = models.CharField('资产组', max_length=255, blank=True, default='')
    asset_name = models.CharField('资产名称', max_length=255, db_index=True, blank=True, default='')
    ip = models.CharField('IP', max_length=64, db_index=True, blank=True, default='')
    admin = models.CharField('管理员', max_length=255, blank=True, default='')
    os = models.CharField('操作系统', max_length=255, blank=True, default='')
    severity = models.IntegerField('风险等级', default=0, db_index=True)  # 0信息/1低/2中/3高/4严重
    name = models.CharField('漏洞名称', max_length=512, db_index=True, blank=True, default='')
    port = models.CharField('端口', max_length=32, blank=True, default='')
    time = models.CharField('发现时间', max_length=64, blank=True, default='')
    rid = models.CharField('漏洞ID', max_length=64, blank=True, default='')
    detail = models.TextField('详情(JSON)', blank=True, default='')
    sync_time = models.DateTimeField('同步时间', auto_now=True)

    class Meta:
        db_table = 'cmdb_vscan_vuln'
        verbose_name = '系统漏洞'
        verbose_name_plural = verbose_name
        ordering = ['severity', 'name']
        indexes = [
            models.Index(fields=['severity']),
            models.Index(fields=['ip']),
        ]

    def __str__(self):
        return f'{self.asset_name}({self.ip}) [{self.severity}] {self.name}'
