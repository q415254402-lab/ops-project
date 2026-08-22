# -*- coding: utf-8 -*-
"""
WEB 漏洞扫描数据落库模型（2026-08-22）
数据来源：华为 vScan（192.168.100.2）scanlogsystem（report 账号），同步到本地 DB
目的：①查询秒开（不再实时拉 vScan 62s）②支持整改对比（多报告 diff）③60 天滚动清理

三表：
  VscanWebTask  任务快照（taskid + 名称 + 扫描时间 + 统计）
  VscanWebSite  网站（queryjob：taskid + URL + 扫描时间）
  VscanWebVuln  漏洞（queryplugin 任务级分页去重：unique(taskid, severity, name, url)）
"""
from django.db import models


class VscanWebTask(models.Model):
    """WEB 扫描任务快照（= 报告批次）"""
    taskid = models.IntegerField('任务ID', unique=True, db_index=True)
    task_name = models.CharField('任务名称', max_length=255, blank=True, default='')
    scan_time = models.DateTimeField('扫描时间', null=True, blank=True)
    site_total = models.IntegerField('网站数', default=0)
    vuln_total = models.IntegerField('漏洞总数(原始)', default=0)
    high_total = models.IntegerField('高危数(等级0)', default=0)
    dedup_total = models.IntegerField('去重漏洞数', default=0)
    sync_time = models.DateTimeField('同步时间', auto_now=True)

    class Meta:
        db_table = 'cmdb_vscan_web_task'
        verbose_name = 'WEB扫描任务'
        verbose_name_plural = verbose_name
        ordering = ['-taskid']

    def __str__(self):
        return f'{self.task_name}({self.taskid})'


class VscanWebSite(models.Model):
    """WEB 扫描网站（queryjob）"""
    taskid = models.IntegerField('任务ID', db_index=True)
    task_name = models.CharField('任务名称', max_length=255, blank=True, default='')
    url = models.CharField('网站URL', max_length=1024, db_index=True)
    jobid = models.CharField('jobid', max_length=64, blank=True, default='')
    scan_time = models.DateTimeField('扫描时间', null=True, blank=True)
    sync_time = models.DateTimeField('同步时间', auto_now=True)

    class Meta:
        db_table = 'cmdb_vscan_web_site'
        verbose_name = 'WEB扫描网站'
        verbose_name_plural = verbose_name
        ordering = ['-taskid']
        unique_together = (('taskid', 'url'),)

    def __str__(self):
        return f'{self.taskid} {self.url}'


class VscanWebVuln(models.Model):
    """WEB 漏洞（queryplugin 任务级分页去重落库）
    unique(taskid, severity, name, url)：同一漏洞×同一 URL 只 1 条，不同 URL 分别记录
    """
    taskid = models.IntegerField('任务ID', db_index=True)
    task_name = models.CharField('任务名称', max_length=255, blank=True, default='')
    severity = models.IntegerField('风险等级', default=0, db_index=True)  # 0高/1中/2低/3信息
    name = models.CharField('漏洞名称', max_length=512, db_index=True)
    url = models.CharField('漏洞URL', max_length=1024, blank=True, default='')
    category = models.CharField('分类', max_length=255, blank=True, default='')
    param = models.TextField('问题参数', blank=True, default='')
    comment = models.TextField('备注', blank=True, default='')
    testcase = models.TextField('测试用例', blank=True, default='')
    pluginid = models.IntegerField('ruleid', default=0, db_index=True)
    scan_time = models.DateTimeField('扫描时间', null=True, blank=True)
    sync_time = models.DateTimeField('同步时间', auto_now=True)

    class Meta:
        db_table = 'cmdb_vscan_web_vuln'
        verbose_name = 'WEB漏洞'
        verbose_name_plural = verbose_name
        ordering = ['taskid', 'severity', 'name']
        unique_together = (('taskid', 'severity', 'name', 'url'),)
        indexes = [
            models.Index(fields=['taskid', 'severity']),
        ]

    def __str__(self):
        return f'{self.taskid} [{self.severity}] {self.name} {self.url}'
