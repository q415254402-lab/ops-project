# -*- coding: utf-8 -*-
"""安全报表 AI 总结引擎（本地大模型，OpenAI 兼容接口）

- 配置走环境变量（config/default.py 注入），缺省指向本地 GPU 网关 10.100.200.130:3000
- 调 /v1/chat/completions，prompt 由 build_report 的 data 构造（只喂关键指标，不喂全量 trend）
- 返回 {text, model, engine:'ai', risk_level}；失败自动降级到规则引擎 report_summary.build_summary
- 仅周报/月报走 AI（日报量大、时效高，用规则引擎毫秒级即可）

环境变量：
  ESIGHT_AI_SUMMARY_ENABLED   1 开 / 0 关（默认 1）
  ESIGHT_AI_BASE_URL          OpenAI 兼容网关地址（默认 http://10.100.200.130:3000）
  ESIGHT_AI_API_KEY           Bearer key
  ESIGHT_AI_MODEL             模型名（默认 qwen3.8-27b-fp8）
  ESIGHT_AI_TIMEOUT           单次调用超时秒（默认 90）
  ESIGHT_AI_MAX_TOKENS        生成上限（默认 900）
"""
import json
import logging
import os
import re
import urllib.request

logger = logging.getLogger('app__ai_summary')

_DEFAULTS = {
    'enabled': '1',
    'base_url': 'http://10.100.200.130:3000',
    # 密钥不写死在源码（安全铁律：敏感凭据一律走 env）。
    # 未配置 ESIGHT_AI_API_KEY 时，generate_summary 自动降级规则引擎，
    # 不会抛异常、不会阻塞，也不会泄露占位符到日志。
    'api_key': '',
    'model': 'qwen3.8-27b-fp8',
    'timeout': 90,
    'max_tokens': 900,
    'temperature': 0.3,
}


def _cfg(key):
    return os.environ.get('ESIGHT_AI_%s' % key.upper(), _DEFAULTS.get(key, ''))


def _enabled():
    return _cfg('enabled') not in ('0', 'false', 'False', '')


def _key_configured():
    """api_key 必须来自 env（源码 _DEFAULTS 置空，不写死密钥）。"""
    return bool(os.environ.get('ESIGHT_AI_API_KEY', '').strip())


def _period_label(pt):
    return {'day': '日报', 'week': '周报', 'month': '月报'}.get(pt, '报表')


def _build_prompt(pt, data):
    """从 build_report 的 data 提取关键指标，构造 user prompt。

    只喂 totals + compare + TOP1，不喂逐日 trend（省 token、避免模型跑偏）。
    """
    mods = data.get('modules') or {}
    cmp_ = data.get('compare') or {}

    def T(m):
        return (mods.get(m) or {}).get('totals') or {}

    def C(m, k):
        return (cmp_.get(m) or {}).get(k) or {}

    waf_t, fw_t, vl_t = T('waf'), T('fw'), T('vuln')
    al_t, ho_t = T('alert'), T('host')

    def cmp_text(item):
        if not item:
            return None
        cur, prev, pct = item.get('cur') or 0, item.get('prev') or 0, item.get('pct')
        if cur == 0 and prev == 0:
            return '两期均为0'
        if prev == 0:
            return '上期0，本期%s（新增）' % cur
        if cur == 0:
            return '本期0，上期%s（清零）' % prev
        if pct is None:
            return '本期%s / 上期%s' % (cur, prev)
        direction = '上升' if pct > 0 else ('下降' if pct < 0 else '持平')
        return '环比%s %s%%（本期%s / 上期%s）' % (direction, abs(pct), cur, prev)

    top_waf = (mods.get('waf') or {}).get('top_src_ip') or [{}]
    top_fw = (mods.get('fw') or {}).get('top_src_ip') or [{}]
    top_vuln = (mods.get('vuln') or {}).get('top_vulns') or [{}]
    err_hosts = (mods.get('host') or {}).get('err_hosts') or []

    compact = {
        '报类型': _period_label(pt),
        '周期': '%s ~ %s' % (data.get('period_start'), data.get('period_end')),
        'WAF攻击': {
            '总数': waf_t.get('total', 0), '高危': waf_t.get('high', 0),
            '环比': cmp_text(C('waf', 'total')),
            'TOP1攻击源': {'ip': top_waf[0].get('label'), '次数': top_waf[0].get('count')} if top_waf and top_waf[0].get('label') else None,
        },
        '防火墙': {
            '总数': fw_t.get('total', 0), '高危': fw_t.get('high', 0),
            '环比': cmp_text(C('fw', 'total')),
            'TOP1来源': {'ip': top_fw[0].get('label'), '次数': top_fw[0].get('count')} if top_fw and top_fw[0].get('label') else None,
        },
        '漏洞扫描': {
            '总数': vl_t.get('total', 0), '高危': vl_t.get('high', 0),
            '系统侧': vl_t.get('sys_total', 0), 'WEB侧': vl_t.get('web_total', 0),
            '环比': cmp_text(C('vuln', 'total')),
            'TOP1漏洞': {'名称': top_vuln[0].get('label'), '数量': top_vuln[0].get('count')} if top_vuln and top_vuln[0].get('label') else None,
        },
        '安全告警': {'扫描次数': al_t.get('total', 0), '有事件': al_t.get('scans_with_event', 0),
                  '环比': cmp_text(C('alert', 'total'))},
        '主机监控': {'纳管': ho_t.get('total', 0), 'SSH异常': ho_t.get('ssh_error', 0),
                  'SNMP异常': ho_t.get('snmp_error', 0),
                  '异常主机': [e.get('label') for e in err_hosts[:3]] or '无',
                  '备注': '主机为当前快照，不随周期变化'},
    }

    sys_prompt = ("你是一名资深安全运营分析师，负责为企业安全运营中心撰写周期安全报告。"
                  "语言专业、客观、简洁，只依据给定数据，不编造，数字用千分位逗号，全程用中文。")
    user_prompt = (
        "以下是一份【{pt}】的安全运营关键数据（JSON，环比已算好）：\n"
        "{json}\n\n"
        "请撰写该周期安全报告总结，结构要求：\n"
        "1. 整体态势概述：3-5 句，先给风险定级（低/中/高），再点明核心结论与最需要关注的点；\n"
        "2. 分模块要点：WAF攻击、防火墙、漏洞扫描、安全告警、主机监控，每模块 2-3 句，突出环比变化与 TOP 对象（IP/漏洞名）；\n"
        "3. 处置建议：3-5 条可落地的加固/排查动作，针对数据中真实存在的风险项。\n"
        "格式：纯文本分 3 个自然段（概述段、模块要点段、建议段），段首用【概述】【要点】【建议】标注；"
        "全文控制在 450 字以内，不要 JSON、不要 markdown、不要编号列表。"
    ).format(pt=_period_label(pt), json=json.dumps(compact, ensure_ascii=False))
    return sys_prompt, user_prompt


def _call_llm(sys_prompt, user_prompt):
    """调 OpenAI 兼容 /v1/chat/completions，返回正文文本。失败抛异常。"""
    base = _cfg('base_url').rstrip('/')
    key = _cfg('api_key')
    model = _cfg('model')
    timeout = int(_cfg('timeout'))
    max_tokens = int(_cfg('max_tokens'))
    temperature = float(_cfg('temperature'))

    body = json.dumps({
        'model': model,
        'messages': [
            {'role': 'system', 'content': sys_prompt},
            {'role': 'user', 'content': user_prompt},
        ],
        'max_tokens': max_tokens,
        'temperature': temperature,
    }).encode('utf-8')
    req = urllib.request.Request(
        base + '/v1/chat/completions', data=body,
        headers={'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        d = json.loads(r.read().decode('utf-8'))
    content = (d.get('choices') or [{}])[0].get('message', {}).get('content')
    if not content:
        raise ValueError('LLM 返回空内容')
    return content.strip()


def _clean_text(text):
    """去除模型可能带出的多余空白 / 引号包裹，保留段落。"""
    if not text:
        return ''
    text = text.strip().strip('`').strip()
    # 去掉首尾成对引号
    if len(text) > 2 and text[0] in '"\u201c\u300c' and text[-1] in '"\u201d\u300d':
        text = text[1:-1].strip()
    # 合并 3+ 连续换行为 2
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text.strip()


def _rule_fallback(pt, data):
    """模型失败时的降级：规则引擎结构化总结 → 拼成与 AI 同形的 text"""
    try:
        from apps.cmdb.report.summary import build_summary
        s = build_summary(data)
        parts = ['【概述】风险定级%s：%s' % (s.get('risk_level', '?'), s.get('overview', ''))]
        for sec in s.get('sections') or []:
            parts.append('【要点】%s：%s' % (sec.get('title', ''), sec.get('text', '')))
        if s.get('advice'):
            parts.append('【建议】' + '；'.join(s['advice']))
        return {'text': '\n\n'.join(parts).strip(), 'model': 'rule-v1', 'engine': 'rule',
                'risk_level': s.get('risk_level')}
    except Exception as e:
        logger.warning('rule fallback also failed for %s: %s', pt, e)
        return {'text': '（总结生成失败：%s）' % e, 'model': 'none', 'engine': 'none',
                'risk_level': None}


def generate_summary(pt, data):
    """主入口：生成周期总结。

    pt: 'day'|'week'|'month'
    data: build_report 的完整输出（modules + compare + period_*）

    返回 dict：{text, model, engine('ai'|'rule'|'none'), risk_level}
    - AI 成功 → engine='ai'
    - AI 失败 → 自动降级规则引擎，engine='rule'
    - 全部失败 → engine='none'
    """
    # 日报走规则引擎（量大时效高，不占模型）；周/月报走 AI
    if pt == 'day' or not _enabled():
        fb = _rule_fallback(pt, data)
        fb['engine'] = 'rule'
        return fb

    # 密钥未配置（env 无 ESIGHT_AI_API_KEY）→ 静默降级规则引擎，不调 LLM。
    # 避免：1) 空 Bearer 发请求浪费超时；2) 日志泄露占位符；3) 阻塞 90s。
    if not _key_configured():
        logger.info('ESIGHT_AI_API_KEY not configured, fallback to rule engine for %s', pt)
        fb = _rule_fallback(pt, data)
        fb['engine'] = 'rule'
        return fb

    sys_prompt, user_prompt = _build_prompt(pt, data)
    try:
        raw = _call_llm(sys_prompt, user_prompt)
        text = _clean_text(raw)
        if len(text) < 20:
            raise ValueError('模型输出过短(%d字)，疑似异常' % len(text))
        # 从模型文本里提取风险定级（概述段常含"风险定级X"/"风险等级X"）
        m = re.search(r'风险(?:定级|等级)[为是：:]*\s*([低中高])', text)
        risk = m.group(1) if m else None
        return {'text': text, 'model': _cfg('model'), 'engine': 'ai', 'risk_level': risk}
    except Exception as e:
        logger.warning('AI summary failed for %s, fallback to rule: %s', pt, e)
        return _rule_fallback(pt, data)


def generate_summary_for_report(report_obj):
    """对已落库的 SecurityReport 生成总结并写回 data['summary']。

    返回 (summary_dict, changed_bool)。
    """
    data = report_obj.get_data() or {}
    if not data:
        return None, False
    summary = generate_summary(report_obj.period_type, data)
    data['summary'] = summary
    report_obj.set_data(data)
    report_obj.save(update_fields=['data'])
    return summary, True
