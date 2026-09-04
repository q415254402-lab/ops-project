# -*- coding: utf-8 -*-
"""安全报表落库模型（日/周/月报）

由 Celery beat 定时任务（apps.cmdb.tasks.gen_reports）生成，也可通过 API 实时计算（不落库）。
data 字段存完整聚合结果（5 模块指标 + TOP + 环比 delta），用 TextField 存 json 字符串，
规避 SQLite JSON1 扩展依赖。
"""
import json
from django.db import models


class SecurityReport(models.Model):
    PERIOD_CHOICES = (
        ('day', '日报'),
        ('week', '周报'),
        ('month', '月报'),
    )
    period_type = models.CharField('报类型', max_length=8, choices=PERIOD_CHOICES, db_index=True)
    period_key = models.CharField('周期键', max_length=32, db_index=True,
                                  help_text='day=2026-09-03 / week=2026-W36 / month=2026-09')
    period_start = models.DateTimeField('周期开始')
    period_end = models.DateTimeField('周期结束')
    title = models.CharField('标题', max_length=128, default='')
    # 完整聚合结果 JSON（5 模块指标 + TOP + 环比），用 TextField 存 json 字符串，规避 SQLite JSON1 依赖
    data = models.TextField('聚合数据', default='{}')
    created_at = models.DateTimeField('生成时间', auto_now_add=True)

    class Meta:
        db_table = 'cmdb_security_report'
        verbose_name = '安全报表'
        verbose_name_plural = verbose_name
        unique_together = (('period_type', 'period_key'),)
        ordering = ['-period_start']

    def __str__(self):
        return u'SecurityReport(%s,%s)' % (self.period_type, self.period_key)

    # data 存取便捷方法（保持 dict 接口）
    def get_data(self):
        try:
            return json.loads(self.data or '{}')
        except Exception:
            return {}

    def set_data(self, d):
        self.data = json.dumps(d, ensure_ascii=False)
