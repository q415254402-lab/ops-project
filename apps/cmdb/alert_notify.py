# -*- coding: utf-8 -*-
"""安全告警通知层：触发通知 + 恢复通知 + 通道可插拔（钉钉/邮件）。

设计要点：
- **恢复通知（resolved）**是大厂告警平台的标配：只报"出事"不报"好了"会让值班人员
  无法判断问题是否仍在持续。此处在事件自动 resolved 时推送恢复消息。
- 通道可插拔且无凭据时静默降级（仅落库不报错），保证测试环境零配置可跑。
- 消息体突出"持续时长/累计次数"，让冷却期内的抑制不丢失信息量。
"""
import logging
import os
import smtplib

import requests

logger = logging.getLogger('app')


def _thr_text(thr):
    return {'high': '高及以上', 'medium': '中及以上', 'low': '低及以上'}.get(thr, thr)


def _status_text(s):
    return {'firing': '触发中', 'acked': '已确认',
            'resolved': '已恢复', 'suppressed': '已忽略'}.get(s, s)


def _fmt_dt(dt):
    return dt.strftime('%Y-%m-%d %H:%M:%S') if dt else '-'


def _duration_text(event, now):
    """事件持续时长（首次出现至今）。"""
    if not event.first_seen:
        return '-'
    mins = int((now - event.first_seen).total_seconds() // 60)
    if mins < 60:
        return u'%d 分钟' % mins
    hours = mins // 60
    if hours < 24:
        return u'%d 小时 %d 分' % (hours, mins % 60)
    return u'%d 天 %d 小时' % (hours // 24, hours % 24)


# ---------------------------------------------------------------- 触发通知
def build_firing_markdown(rule, rec, events, detail, now):
    L = []
    new_cnt = rec.events_new
    rec_cnt = len([1 for _e, k in events if k == 'recur'])
    L.append(u'## eSight 安全告警（触发）')
    L.append(u'- 检测窗口：近 **%d** 分钟（阈值：%s）' % (
        rule.window_minutes, _thr_text(rule.severity_threshold)))
    L.append(u'- 时间窗内命中：WAF **%d** 条 / 防火墙 **%d** 条' % (rec.waf_new, rec.fw_new))
    L.append(u'- 事件维度：新增 **%d** 个 / 复现 **%d** 个 / 冷却抑制 **%d** 个' % (
        new_cnt, rec_cnt, rec.events_suppressed))
    L.append(u'- 系统漏洞高危（现状）：%d 条；WEB 漏洞高危（现状）：%d 条' % (
        rec.vuln_high, rec.web_high))
    L.append(u'')
    L.append(u'### 告警事件（按窗口内命中数排序）')
    for ev, kind in events[:8]:
        tag = u'新增' if kind == 'new' else u'持续'
        L.append(u'- **[%s]** `%s` %s' % (tag, ev.source, ev.event_type or '(未知类型)'))
        L.append(u'  - 源 `%s` → 目的 `%s`，级别 `%s`' % (
            ev.src_ip or '-', ev.dst_ip or '-', ev.severity or '-'))
        L.append(u'  - 累计 **%d** 次，持续 %s' % (ev.occurrence, _duration_text(ev, now)))
    if len(events) > 8:
        L.append(u'- ... 另有 %d 个事件' % (len(events) - 8))
    return u'\n'.join(L)


# ---------------------------------------------------------------- 恢复通知
def build_resolved_markdown(rule, resolved_list, now):
    L = []
    L.append(u'## eSight 安全告警（已恢复）')
    L.append(u'- 以下事件已超过 **%d** 分钟未再出现，判定为恢复' % rule.resolve_after_minutes)
    L.append(u'')
    for ev in resolved_list[:10]:
        L.append(u'- `%s` %s' % (ev.source, ev.event_type or '(未知类型)'))
        L.append(u'  - 源 `%s` → 目的 `%s`，累计 **%d** 次，恢复于 %s' % (
            ev.src_ip or '-', ev.dst_ip or '-', ev.occurrence, _fmt_dt(ev.resolved_at)))
    if len(resolved_list) > 10:
        L.append(u'- ... 另有 %d 个事件恢复' % (len(resolved_list) - 10))
    return u'\n'.join(L)


# ---------------------------------------------------------------- 通道
def notify_firing(rule, rec, events, detail, now):
    channels = []
    md = build_firing_markdown(rule, rec, events, detail, now)

    dt_url = (rule.dingtalk_webhook or os.getenv('DINGTALK_WEBHOOK', '')).strip()
    if rule.dingtalk_enabled and dt_url:
        if _send_dingtalk(dt_url, md):
            channels.append('dingtalk')

    to = (rule.email_to or os.getenv('ALERT_EMAIL_TO', '')).strip()
    if rule.email_enabled and to:
        subject = u'%s 新增 %d / 持续 %d 个事件' % (
            rule.email_subject_prefix, rec.events_new,
            len([1 for _e, k in events if k == 'recur']))
        if _send_email(to, subject, md):
            channels.append('email')

    if not channels:
        logger.info('无可用推送通道，仅落库: rec=%s', rec.id)
    return channels


def notify_resolved(rule, resolved_list, now):
    channels = []
    md = build_resolved_markdown(rule, resolved_list, now)

    dt_url = (rule.dingtalk_webhook or os.getenv('DINGTALK_WEBHOOK', '')).strip()
    if rule.dingtalk_enabled and dt_url:
        if _send_dingtalk(dt_url, md):
            channels.append('dingtalk')

    to = (rule.email_to or os.getenv('ALERT_EMAIL_TO', '')).strip()
    if rule.email_enabled and to:
        subject = u'%s %d 个事件已恢复' % (rule.email_subject_prefix, len(resolved_list))
        if _send_email(to, subject, md):
            channels.append('email')
    return channels


def _send_dingtalk(webhook, markdown_text):
    payload = {
        'msgtype': 'markdown',
        'markdown': {'title': u'eSight 安全告警', 'text': markdown_text},
    }
    try:
        r = requests.post(webhook, json=payload, timeout=10)
        ok = (r.status_code == 200)
        logger.info('dingtalk send status=%s', r.status_code)
        return ok
    except Exception as e:
        logger.error('dingtalk send failed: %s', e)
        return False


def _send_email(to, subject, body):
    host = os.getenv('SMTP_HOST')
    if not host:
        logger.warning('SMTP_HOST 未配置，跳过邮件发送')
        return False
    port = int(os.getenv('SMTP_PORT', '465'))
    user = os.getenv('SMTP_USER', '')
    pwd = os.getenv('SMTP_PASS', '')
    use_ssl = os.getenv('SMTP_USE_SSL', '1') == '1'
    try:
        from email.mime.text import MIMEText
        msg = MIMEText(body, 'plain', 'utf-8')
        msg['Subject'] = subject
        msg['From'] = user
        msg['To'] = to
        recipients = [x.strip() for x in to.split(',') if x.strip()]
        if use_ssl:
            with smtplib.SMTP_SSL(host, port, timeout=10) as s:
                if user:
                    s.login(user, pwd)
                s.sendmail(user or to, recipients, msg.as_string())
        else:
            with smtplib.SMTP(host, port, timeout=10) as s:
                if user:
                    s.login(user, pwd)
                s.sendmail(user or to, recipients, msg.as_string())
        logger.info('email sent to %s', to)
        return True
    except Exception as e:
        logger.error('email send failed: %s', e)
        return False
