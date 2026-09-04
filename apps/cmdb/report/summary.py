# -*- coding: utf-8 -*-
"""安全报表规则总结引擎（不依赖大模型）

输入 build_report 的 data（modules + compare），输出中文总结：
  {risk_level, overview, sections:[{module,title,text}], advice:[...]}

设计原则：
  - 全部基于阈值 + 模板的确定性输出（可复现、零外部依赖、毫秒级）
  - 数字一律千分位逗号，与前端 fmt() 一致
  - 环比语义与前端 cmp() 一致：两期皆 0 不提；上期 0 本期>0 说"新增"；持平说"持平"
"""


def _n(v):
    try:
        return '{:,}'.format(int(v or 0))
    except (TypeError, ValueError):
        return '0'


def _cmp_text(cmp_item, unit='次'):
    """环比短语：返回 '' 或 '，较上期上升 82.4%' 之类"""
    if not cmp_item:
        return ''
    cur = cmp_item.get('cur') or 0
    prev = cmp_item.get('prev') or 0
    pct = cmp_item.get('pct')
    if cur == 0 and prev == 0:
        return ''
    if prev == 0:
        return '，较上期新增 %s %s' % (_n(cur), unit)
    if cur == 0:
        return '，较上期下降 100%'
    if pct is None:
        return ''
    if pct > 0:
        return '，较上期上升 %s%%' % _n(pct)
    if pct < 0:
        return '，较上期下降 %s%%' % _n(abs(pct))
    return '，与上期持平'


def _top_text(top_list, total):
    """TOP1 贡献占比描述；返回 '' 或 '，其中 1.1.1.1 贡献最多（20 次，占 4.9%）'"""
    if not top_list or not total:
        return ''
    first = top_list[0]
    cnt = first.get('count') or 0
    if cnt <= 0:
        return ''
    pct = cnt * 100.0 / total
    if pct < 1:
        return ''
    return '，其中 %s 贡献最多（%s 次，占 %.1f%%）' % (first.get('label', '?'), _n(cnt), pct)


def _trend_text(trend):
    """周期内逐日走势定性：找峰值日；返回 '' 或 '，峰值出现在 08-28（1,070 次）'"""
    if not trend:
        return ''
    peak = max(trend, key=lambda d: d.get('count') or 0)
    c = peak.get('count') or 0
    if c <= 0:
        return ''
    return '，周期内峰值出现在 %s（%s 次）' % (peak.get('date', '?')[5:], _n(c))


# 阈值（可按现场规模调整）
_TH = {
    'waf_total_high': 1000, 'waf_total_mid': 300,
    'fw_total_high': 1000, 'fw_total_mid': 300,
    'share_top': 30.0,       # TOP1 占比超过 30% 视为集中攻击
    'rise_pct': 50.0,        # 环比上升超过 50% 视为显著上升
}

_SEV_ORDER = ['严重', '高', '中', '低', '信息']


def _sev_brief(sev_dist, top=2):
    """严重度分布短语：'高危 2,545 / 中 5,286' 取前两档非零"""
    if not sev_dist:
        return ''
    m = {s.get('name'): s.get('value') or 0 for s in sev_dist}
    parts = []
    for name in _SEV_ORDER:
        v = m.get(name) or 0
        if v > 0:
            label = '高危' if name in ('高', '严重') else (name + '危' if name == '低' else name)
            parts.append('%s %s' % (label, _n(v)))
        if len(parts) >= top:
            break
    return '（%s）' % '，'.join(parts) if parts else ''


def _finish(text):
    """句子收尾：确保恰好以一个句号结束"""
    text = text.rstrip('。')
    return text + '。' if text else text


def summarize_waf(mod, cmp_):
    t = mod.get('totals') or {}
    total, high = t.get('total') or 0, t.get('high') or 0
    if total == 0:
        return '当期未捕获 WAF 攻击事件。'
    level = '攻击量处于高位' if total >= _TH['waf_total_high'] else (
        '攻击量处于中等水平' if total >= _TH['waf_total_mid'] else '攻击量整体可控')
    text = '共拦截 WAF 攻击 %s 次%s，其中高危 %s 次%s。%s%s%s%s' % (
        _n(total), _cmp_text(cmp_.get('total')), _n(high), _cmp_text(cmp_.get('high')),
        level, _sev_brief(mod.get('severity_dist')),
        _top_text(mod.get('top_src_ip'), total), _trend_text(mod.get('trend')))
    return _finish(text)


def summarize_fw(mod, cmp_):
    t = mod.get('totals') or {}
    total, high = t.get('total') or 0, t.get('high') or 0
    if total == 0:
        return '当期未捕获防火墙拦截事件。'
    level = '拦截量处于高位' if total >= _TH['fw_total_high'] else (
        '拦截量处于中等水平' if total >= _TH['fw_total_mid'] else '拦截量整体平稳')
    text = '防火墙共拦截 %s 次%s，其中高危 %s 次%s。%s%s%s%s' % (
        _n(total), _cmp_text(cmp_.get('total')), _n(high), _cmp_text(cmp_.get('high')),
        level, _sev_brief(mod.get('severity_dist')),
        _top_text(mod.get('top_src_ip'), total), _trend_text(mod.get('trend')))
    return _finish(text)


def summarize_vuln(mod, cmp_):
    t = mod.get('totals') or {}
    total = t.get('total') or 0
    sys_total, web_total = t.get('sys_total') or 0, t.get('web_total') or 0
    high = t.get('high') or 0
    if total == 0:
        return '当期未同步到新增漏洞（vScan 按扫描任务入库，非扫描日无新增属正常）。'
    text = '当期新增漏洞 %s 个%s，其中高危 %s 个%s（系统侧 %s、WEB 侧 %s）。' % (
        _n(total), _cmp_text(cmp_.get('total'), '个'), _n(high), _cmp_text(cmp_.get('high'), '个'),
        _n(sys_total), _n(web_total))
    top = (mod.get('top_vulns') or [])
    if top:
        text += '风险最集中的是「%s」（%s 个）' % (top[0].get('label', '?'), _n(top[0].get('count')))
        if len(top) > 1:
            text += '，其次为「%s」（%s 个）' % (top[1].get('label', '?'), _n(top[1].get('count')))
        text += '。'
    return text


def summarize_alert(mod, cmp_):
    t = mod.get('totals') or {}
    total = t.get('total') or 0
    ev = t.get('scans_with_event') or 0
    if total == 0:
        return '当期未执行告警扫描。'
    text = '共执行安全巡检 %s 次%s，其中 %s 次发现新事件%s。' % (
        _n(total), _cmp_text(cmp_.get('total')), _n(ev), _cmp_text(cmp_.get('scans_with_event')))
    latest = mod.get('latest')
    if latest and latest.get('scan_time'):
        text += '最近一次巡检 %s' % latest.get('scan_time')
        detail = []
        if latest.get('waf_new'):
            detail.append('WAF 新增 %s' % _n(latest['waf_new']))
        if latest.get('fw_new'):
            detail.append('防火墙新增 %s' % _n(latest['fw_new']))
        if latest.get('vuln_high'):
            detail.append('系统高危漏洞 %s' % _n(latest['vuln_high']))
        if latest.get('web_high'):
            detail.append('WEB 高危漏洞 %s' % _n(latest['web_high']))
        text += ('：' + '，'.join(detail)) if detail else '未发现新增风险'
        text += '。'
    return text


def summarize_host(mod, cmp_):
    t = mod.get('totals') or {}
    total = t.get('total') or 0
    ssh_err, snmp_err = t.get('ssh_error') or 0, t.get('snmp_error') or 0
    text = '纳管主机 %s 台' % _n(total)
    if ssh_err == 0 and snmp_err == 0:
        text += '，SSH / SNMP 采集全部正常（注意：主机为当前快照，不随所选周期变化）。'
        return text
    text += '，当前 SSH 异常 %s 台、SNMP 异常 %s 台' % (_n(ssh_err), _n(snmp_err))
    errs = mod.get('err_hosts') or []
    if errs:
        text += '（如 %s）' % '、'.join((e.get('label') or '?') for e in errs[:2])
    text += '。注意：主机为当前快照，不随所选周期变化。'
    return text


_SUMMARIZERS = {
    'waf': ('WAF 攻击防护', summarize_waf),
    'fw': ('防火墙拦截', summarize_fw),
    'vuln': ('漏洞扫描', summarize_vuln),
    'alert': ('安全告警巡检', summarize_alert),
    'host': ('主机监控', summarize_host),
}


def _risk_level(data):
    """整体风险定级：高危攻击/漏洞 > 阈值 → 高；有异常 → 中；否则 低"""
    mods = data.get('modules') or {}
    waf_total = ((mods.get('waf') or {}).get('totals') or {}).get('total') or 0
    waf_high = ((mods.get('waf') or {}).get('totals') or {}).get('high') or 0
    fw_total = ((mods.get('fw') or {}).get('totals') or {}).get('total') or 0
    vuln_high = ((mods.get('vuln') or {}).get('totals') or {}).get('high') or 0
    host_err = (((mods.get('host') or {}).get('totals') or {}).get('ssh_error') or 0) + \
               (((mods.get('host') or {}).get('totals') or {}).get('snmp_error') or 0)
    if vuln_high > 0 or waf_high > 0 or host_err > 0:
        return '高'
    if waf_total >= _TH['waf_total_high'] or fw_total >= _TH['fw_total_high']:
        return '中'
    return '低'


def build_advice(data):
    """规则化处置建议"""
    mods = data.get('modules') or {}
    cmp_ = data.get('compare') or {}
    advice = []

    waf = mods.get('waf') or {}
    waf_t = waf.get('totals') or {}
    if (waf_t.get('high') or 0) > 0:
        top = (waf.get('top_src_ip') or [{}])[0].get('label')
        advice.append('存在高危 WAF 攻击，建议优先核查 TOP 攻击源 %s 并确认封禁策略生效' % (top or 'IP'))
    waf_cmp = (cmp_.get('waf') or {}).get('total') or {}
    if (waf_cmp.get('pct') or 0) >= _TH['rise_pct']:
        advice.append('WAF 攻击量环比上升 %.0f%%，建议确认是否为新业务上线暴露或扫描行为' % waf_cmp['pct'])

    fw_t = (mods.get('fw') or {}).get('totals') or {}
    if (fw_t.get('total') or 0) >= _TH['fw_total_high']:
        advice.append('防火墙拦截量处于高位，建议关注出口带宽与策略命中情况')

    vuln_t = (mods.get('vuln') or {}).get('totals') or {}
    if (vuln_t.get('high') or 0) > 0:
        advice.append('存在 %s 个高危漏洞，建议按「系统侧优先、WEB 侧次之」排期修复' % _n(vuln_t['high']))

    alert_t = (mods.get('alert') or {}).get('totals') or {}
    if alert_t.get('total') and not alert_t.get('scans_with_event'):
        advice.append('巡检未发现新增事件，安全态势平稳，维持现有策略即可')

    host_t = (mods.get('host') or {}).get('totals') or {}
    if (host_t.get('snmp_error') or 0) > 0:
        advice.append('%s 台主机 SNMP 采集异常，建议检查团体字配置与 UDP 161 连通性' % _n(host_t['snmp_error']))
    if (host_t.get('ssh_error') or 0) > 0:
        advice.append('%s 台主机 SSH 采集异常，建议检查账号密码与管理地址可达性' % _n(host_t['ssh_error']))

    if not advice:
        advice.append('整体态势平稳，无需要立即处置的风险项')
    return advice


def build_summary(data):
    """主入口：data = build_report 输出（modules + compare）"""
    mods = data.get('modules') or {}
    cmp_ = data.get('compare') or {}

    sections = []
    for key, (title, fn) in _SUMMARIZERS.items():
        mod = mods.get(key) or {}
        try:
            text = fn(mod, cmp_.get(key) or {})
        except Exception as e:  # 单模块失败不影响整体
            text = '（本模块总结生成失败：%s）' % e
        sections.append({'module': key, 'title': title, 'text': text})

    # 总述：主指标串联
    waf_t = (mods.get('waf') or {}).get('totals') or {}
    fw_t = (mods.get('fw') or {}).get('totals') or {}
    vuln_t = (mods.get('vuln') or {}).get('totals') or {}
    overview = '本期共拦截 WAF 攻击 %s 次、防火墙拦截 %s 次，新增漏洞 %s 个（高危 %s 个）。' % (
        _n(waf_t.get('total')), _n(fw_t.get('total')),
        _n(vuln_t.get('total')), _n(vuln_t.get('high')))

    return {
        'risk_level': _risk_level(data),
        'overview': overview,
        'sections': sections,
        'advice': build_advice(data),
        'engine': 'rule-v1',
    }
