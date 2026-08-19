# -*- coding: utf-8 -*-
"""
WAF 攻击日志 Syslog 解析器（2026-08-17）
解析绿盟日志审计系统（LAS）转发的日志，兼容两种格式：
1. Key-Value 格式：<11>Mar 17 14:07:40 host sas-l: msg=xxx;date=123;sip=1.2.3.4;dip=5.6.7.8;...
2. JSON 格式：{"dev_id": "...", "msg": "...", "sip": "...", ...}
字段兼容映射见 waf_security.py 模块注释。
"""
import json
import logging
import re
import time
from datetime import datetime, timezone, timedelta

from django.utils import timezone as dj_timezone

logger = logging.getLogger('app')

# LAS 前缀：<PRI>MMM dd HH:MM:SS hostname sas-l: 实际内容
_PREFIX_RE = re.compile(r'^<(?P<pri>\d+)>\S+\s+\S+\s+\S+\s+(?P<body>.*)$', re.DOTALL)

# Key-Value：key=value; —— 2026-08-17 华为日志 raw_data 含嵌套引号（Extend=""），
# 简单正则会在引号处截断，raw_data/desc 用专门的贪婪正则提取完整引号内容
_KV_RE = re.compile(r'(?P<key>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>[^;]*)')
_RAW_RE = re.compile(r'raw_data="(?P<v>.*)";', re.DOTALL)
_DESC_RE = re.compile(r'desc="(?P<v>.*)";', re.DOTALL)

# 华为 USG 原始日志字段（raw_data/desc 内，大写驼峰）
_HW_SRCIP = re.compile(r'SrcIp\s*=\s*([0-9.]+)')
_HW_DSTIP = re.compile(r'DstIp\s*=\s*([0-9.]+)')
_HW_SRCPORT = re.compile(r'SrcPort\s*=\s*(\d+)')
_HW_DSTPORT = re.compile(r'DstPort\s*=\s*(\d+)')
_HW_SIGN = re.compile(r'SignName\s*=\s*"([^"]+)"')
_HW_SEV = re.compile(r'Severity\s*=\s*(\w+)')
_HW_ACT = re.compile(r'Action\s*=\s*(\w+)')
_HW_CAT = re.compile(r'Category\s*=\s*(\w+)')


# 2026-08-17：WAF action 数字编码 → 中文（绿盟 WAF 实际约定）
# 1=告警/记录 2=阻断 3=放行 4=隔离
_WAF_ACTION_MAP = {
    '0': '告警', '1': '告警', '2': '阻断', '3': '放行',
    '4': '隔离', '5': '重置', '6': '重定向',
}


# 2026-08-18：WAF risk 数字编码 → 风险级别（绿盟约定：数字越小越严重，1=高/2=中/3=低/4=严重，0=未评估）
_WAF_RISK_MAP = {'0': '中', '1': '高', '2': '中', '3': '低', '4': '严重', '5': '严重'}


def _map_waf_risk(raw):
    """WAF risk 数字 → 中文（绿盟约定：1=高, 2=中, 3=低）"""
    if not raw:
        return ''
    s = str(raw).strip()
    if s in _WAF_RISK_MAP:
        return _WAF_RISK_MAP[s]
    low = s.lower()
    if low in ('high', 'h', 'critical', 'crit', '严重'):
        return '高'
    if low in ('medium', 'med', 'mid', '中'):
        return '中'
    if low in ('low', 'l', 'info', '低'):
        return '低'
    return s


def _map_waf_action(raw):
    """action 字段：字符串/数字/英文都映射成中文"""
    if not raw:
        return ''
    s = str(raw).strip()
    if s in _WAF_ACTION_MAP:
        return _WAF_ACTION_MAP[s]
    # 已经是中文/英文，按需翻译
    low = s.lower()
    if low in ('block', 'deny', '阻断'):
        return '阻断'
    if low in ('allow', 'permit', 'pass', '放行'):
        return '放行'
    if low in ('alert', '告警'):
        return '告警'
    if low in ('drop', '丢弃'):
        return '丢弃'
    if low in ('reset', '重置'):
        return '重置'
    return s


def _parse_date(ts):
    """兼容：秒时间戳 / 毫秒时间戳 / 字符串时间 / Excel 序列号"""
    if not ts:
        return None
    try:
        ts = str(ts).strip()
        # 纯数字
        if ts.isdigit():
            t = int(ts)
            if t > 10 ** 12:  # 毫秒
                t = t / 1000
            if t > 10 ** 9:  # 秒级时间戳（约 2001 年之后）
                return datetime.fromtimestamp(t, tz=timezone.utc).astimezone()
            # Excel 序列号（如 43907.57853009259）
            if t < 60000:
                excel_epoch = datetime(1899, 12, 30, tzinfo=timezone.utc)
                return (excel_epoch + timedelta(days=float(ts))).astimezone()
        # 字符串时间
        for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M', '%m/%d/%Y %H:%M:%S'):
            try:
                return datetime.strptime(ts, fmt).replace(tzinfo=dj_timezone.get_current_timezone())
            except ValueError:
                continue
    except Exception:
        pass
    return None


def parse_syslog_line(line):
    """解析一行 syslog（Key-Value 或 JSON），返回 dict 或 None"""
    if not line or not line.strip():
        return None
    line = line.strip()
    # 剥离 <PRI> 前缀（如果有）
    m = _PREFIX_RE.match(line)
    if m:
        body = m.group('body').strip()
    else:
        body = line
    # 尝试 JSON
    if body.startswith('{'):
        try:
            data = json.loads(body)
            return _normalize(data)
        except Exception:
            pass
    # Key-Value
    kv = {}
    for m in _KV_RE.finditer(body):
        kv[m.group('key')] = m.group('value').strip()
    # 2026-08-17：raw_data/desc 用专门正则提取（含嵌套引号，KV 简单正则会截断）
    m_raw = _RAW_RE.search(body)
    if m_raw:
        kv['raw_data'] = m_raw.group('v').strip()
    m_desc = _DESC_RE.search(body)
    if m_desc:
        kv['desc'] = m_desc.group('v').strip()
    if not kv:
        return None
    return _normalize(kv)


def _normalize(d):
    """字段兼容映射 → 标准字段"""
    def g(*keys):
        for k in keys:
            if k in d and d[k] not in (None, '', ' '):
                return d[k]
        return ''

    def _int(v, default=0):
        try:
            return int(float(v))
        except (TypeError, ValueError):
            return default

    # 华为 USG 原始日志（raw_data/desc 内）提取——2026-08-17
    raw = g('raw_data', 'desc', 'raw', 'rawinfo')
    hw_src = _HW_SRCIP.search(raw) if raw else None
    hw_dst = _HW_DSTIP.search(raw) if raw else None
    hw_srcport = _HW_SRCPORT.search(raw) if raw else None
    hw_dstport = _HW_DSTPORT.search(raw) if raw else None
    hw_sign = _HW_SIGN.search(raw) if raw else None
    hw_sev = _HW_SEV.search(raw) if raw else None
    hw_act = _HW_ACT.search(raw) if raw else None
    hw_cat = _HW_CAT.search(raw) if raw else None

    abstract = g('abstract', 'log_type', 'module')
    # 华为 abstract=IPS/4/WORM → 模块名（IPS）
    abstract_mod = abstract.split('/')[0] if abstract else ''

    # 2026-08-17：WAF 真实日志字段（LAS 推过来的 JSON 格式，字段丰富）
    rule_name = g('rule_name')                       # WAF 攻击规则名（如 "No rule"）
    site_name = g('site_name')                       # 防护站点（"邮件服务器"）
    src_country = g('src_country')                   # 攻击源国家
    block_info = g('block_info')                     # 阻断详情
    block_val = g('block')                           # 是否阻断（0/1）
    protocol_type = g('protocol_type', 'ProtocolType')
    msgtype = g('msgtype')                           # WAF 消息类型
    event_type_mapping = g('event_type_mapping')     # ⭐ WAF 已提供中文事件类型（"HTTP协议校验"）
    policy_name = g('policy_name')                   # ⭐ 策略名称（"攻防演练高频高危模板"）
    policy_desc = g('policy_desc')                   # 策略描述
    alert_info = g('alert_info', 'alertinfo')        # ⭐ 告警信息（攻击特征英文代码）
    risk_raw = g('risk')                             # ⭐ 风险级别（数字 1-4）
    asset_name = g('资产名称', 'asset_name')          # 资产名称
    device_vendor = g('设备厂商', 'device_vendor')    # 设备厂商
    device_version = g('设备型号/版本', 'device_version')  # 设备版本

    sev_raw = g('gr_danger_mapping', 'severity', 'danger_level', 'alertlevel') or (hw_sev.group(1) if hw_sev else '') or _map_waf_risk(risk_raw)
    out = {
        'src_ip': g('sip', 'src_ip', 'source_ip', 'raw_client_ip') or (hw_src.group(1) if hw_src else ''),
        'src_port': str(g('sport', 'src_port', 'source_port')) or (hw_srcport.group(1) if hw_srcport else ''),
        'dst_ip': g('dip', 'dst_ip', 'dest_ip', 'destination_ip', 'devip') or (hw_dst.group(1) if hw_dst else ''),
        'dst_port': str(g('dport', 'dst_port', 'dest_port')) or (hw_dstport.group(1) if hw_dstport else ''),
        # 2026-08-17 v2：event_type 优先级——WAF 中文事件类型 > 策略名 > 规则名 > 攻击类映射 > 抽象模块
        'event_type': event_type_mapping or policy_name or rule_name or g('gr_type_mapping', 'event_type', 'attack_type', 'threat_type') or (hw_sign.group(1) if hw_sign else abstract_mod or ''),
        'event_type_id': _int(g('gr_type', 'event_type_id') or g('event_type')),
        'severity': sev_raw,
        'severity_id': _int(g('gr_danger', 'severity_id') or risk_raw),
        'action': _map_waf_action(g('action_mapping', 'action', 'action_name') or (hw_act.group(1) if hw_act else '')),
        'action_id': _int(g('action_id', 'act') or g('action')),
        # 2026-08-17 v2：msg 优先级——告警信息（最具体的攻击特征）> 策略名 > 规则名 > 阻断详情
        'msg': alert_info or g('msg', 'message', 'description', 'event_name', 'desc') or policy_name or (hw_cat.group(1) if hw_cat else rule_name or block_info or ''),
        'rule_id': str(g('rule_id', 'policy_id', 'SignId', 'sign_id')),
        'proto': protocol_type or g('proto', 'protocol', 'Protocol'),
        'method': g('method', 'http_method'),
        'domain': g('domain', 'hostname', 'vhost', 'Host'),
        'uri': g('uri', 'url', 'request_uri', 'path', 'url'),
        'dev_ip': g('dev_ip', 'device_ip', 'log_ip', 'src_dev_ip', 'devip'),
        'dev_id': g('dev_id', 'device_id', 'device_hash'),
        # 2026-08-17 v2：WAF 扩展字段
        'site_name': site_name,
        'src_country': src_country,
        'protocol_type': protocol_type,
        'alert_info': alert_info,
        'policy_name': policy_name,
        # 2026-08-17：华为防火墙过滤用（LAS 解析的日志类型，如 POLICY/6/POLICYPERMIT、IPS/4/WORM）——不落库
        'abstract': abstract,
        'raw': raw if raw else (json.dumps(d, ensure_ascii=False) if isinstance(d, dict) else str(d)),
    }
    # 时间
    lt = _parse_date(g('log_date', 'date', 'timestamp', 'stat_time', 'time', 'create_time'))
    if lt:
        out['log_time'] = lt
    return out
