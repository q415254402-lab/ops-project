// eSight 安全告警 SPA（Vue 2 全局构建）— 2026-08-28 深化版
// 数据源：/t/esight/api/v1/cmdb/security/alert/
(function () {
  'use strict';

  var API = {
    rule: '/t/esight/api/v1/cmdb/security/alert/rule/',
    scan: '/t/esight/api/v1/cmdb/security/alert/scan/',
    records: '/t/esight/api/v1/cmdb/security/alert/records/',
    events: '/t/esight/api/v1/cmdb/security/alert/events/',
    action: '/t/esight/api/v1/cmdb/security/alert/events/action/',
    stats: '/t/esight/api/v1/cmdb/security/alert/events/stats/',
    detail: '/t/esight/api/v1/cmdb/security/alert/events/detail/',
  };

  var STATUS_TEXT = {
    firing: '触发中', acked: '已确认', resolved: '已恢复', suppressed: '已忽略'
  };

  // ===== 中文翻译层（仅展示，不动数据/指纹） =====
  var SEV_TEXT = {
    'high': '高危', '高': '高危', 'critical': '紧急', '紧急': '紧急',
    'medium': '中危', '中': '中危', 'low': '低危', '低': '低危',
    'unknown': '未知', '': '未知'
  };
  function severityText(s) { return SEV_TEXT[s] || (s ? s : '未知'); }

  var SRC_TEXT = { 'WAF': 'WAF攻击日志', 'Firewall': '防火墙日志', '漏洞扫描': '漏洞扫描' };
  function sourceText(s) { return SRC_TEXT[s] || s || '-'; }

  // 攻击类型：精确映射（覆盖数据库现有类型，给出专业中文名）
  var ET_EXACT = {
    'Worm Xred: xred.mooo.com': 'Xred 蠕虫 (xred.mooo.com)',
    'Botnet: Mirai': '僵尸网络: Mirai',
    'Botnet Mozi Vulnerability Scan Traffic detected': 'Mozi 僵尸网络扫描流量',
    'Malware: AndroxGh0st': 'AndroxGh0st 恶意软件',
    'JAWS DVR CCTV Shell Command Execution': 'JAWS DVR 监控设备命令执行漏洞',
    'Zgrab Scan Network Attempt': 'Zgrab 网络扫描尝试',
    'Web Application Scanner - Nmap Script': 'Nmap Web 应用扫描',
    'SSL Random Scanner - Nmap Script': 'Nmap SSL 随机扫描',
    'Web Scanner: Censys': 'Censys Web 扫描器',
    'Masscan Scanner - Protocol SSL': 'Masscan SSL 扫描',
    'Feroxbuster scanner traffic Detected': 'Feroxbuster 目录扫描流量',
    'Scanning Traffic: T3 Protocol': 'T3 协议扫描流量',
    'HTTP协议校验': 'HTTP 协议校验',
    'URL': 'URL 访问',
    '路径穿越防护': '路径穿越防护',
    'Web服务器漏洞': 'Web 服务器漏洞',
    'Web插件漏洞': 'Web 插件漏洞',
    '命令行注入攻击(语义分析)': '命令行注入攻击 (语义分析)',
    '命令行注入防护': '命令行注入防护',
    '扫描防护': '扫描防护',
    'SQL注入防护': 'SQL 注入防护',
    'Spring Boot Actuator Unauthorized Access Vulnerability': 'Spring Boot Actuator 未授权访问漏洞',
    'Apache HTTP Server CVE-2021-41773 Directory Traversal Vulnerability': 'Apache HTTP Server CVE-2021-41773 目录穿越漏洞',
    'Apache Shiro CVE-2023-34478 Authentication Bypass Vulnerability': 'Apache Shiro CVE-2023-34478 身份验证绕过漏洞',
    'Apache Shiro CVE-2020-1957 Authentication Bypass': 'Apache Shiro CVE-2020-1957 身份验证绕过',
    'Apache Solr Cores Information Disclosure Attempt - GET Core List': 'Apache Solr 核心信息泄露尝试',
    'Cisco IOS HTTP Authentication Bypass': 'Cisco IOS HTTP 身份验证绕过',
    'Cisco IOS XE Web UI CVE-2023-20198 Privilege Escalation Vulnerability': 'Cisco IOS XE Web UI CVE-2023-20198 权限提升漏洞',
    'D-Link Router Products Information Disclosure': 'D-Link 路由器信息泄露',
    'D-Link Devices HNAP SOAPAction-Header Command Execution': 'D-Link 设备 HNAP 命令执行',
    'GPON Home Router CVE-2018-10561 Authentication Bypass': 'GPON 家用路由器 CVE-2018-10561 身份验证绕过',
    'NetLink GPON Multiple Routers formLogin Remote Command Injection Vulnerability': 'NetLink GPON 路由器 formLogin 远程命令注入漏洞',
    'Netgear DGN1000 And Netgear DGN2200 Command Execution Vulnerability': 'Netgear DGN1000/DGN2200 命令执行漏洞',
    'TP-Link Archer AX21 command CVE-2023-1389 Command Injection Vulnerability': 'TP-Link Archer AX21 CVE-2023-1389 命令注入漏洞',
    'Hikvision Product CVE-2021-36260 Command Injection Vulnerability': '海康威视 CVE-2021-36260 命令注入漏洞',
    'Hongdian H8922 Industrial Router CVE-2021-28151 Command Injection Vulnerability': '宏电 H8922 工业路由器 CVE-2021-28151 命令注入漏洞',
    'PHP PHP-CGI Module Parameter Injection Code Execution': 'PHP PHP-CGI 参数注入代码执行',
    'PHP-CGI CVE-2024-4577 Command Injection Vulnerability (-d)': 'PHP-CGI CVE-2024-4577 命令注入漏洞',
    'ThinkPHP Controller Parameter Remote Code Execution': 'ThinkPHP 控制器参数远程代码执行',
    'ThinkPHP Request Method Remote Code Execution Vulnerability': 'ThinkPHP 请求方法远程代码执行漏洞',
    'Thinkphp Lang Function Remote Code Execution Vulnerability': 'ThinkPHP Lang 函数远程代码执行漏洞',
    'Next.js CVE-2020-5284 Directory Traversal Vulnerability': 'Next.js CVE-2020-5284 目录穿越漏洞',
    'React/Next.js Server Remote Code Execution Vulnerability': 'React/Next.js 服务端远程代码执行漏洞',
    'Vite raw CVE-2025-30208 Unauthorized Access Vulnerability': 'Vite CVE-2025-30208 未授权访问漏洞',
    'Ruijie Easy Gateway Information Disclosure Vulnerability': '锐捷易网关信息泄露漏洞',
    'Ruijie RG-UAC CVE-2023-7304 Command Injection Vulnerability': '锐捷 RG-UAC CVE-2023-7304 命令注入漏洞',
    'Sangfor EDR c.php Remote Code Execution Vulnerability': '深信服 EDR c.php 远程代码执行漏洞',
    'Weaver e-cology OA and Yonyou NC System BshServlet Remote Code Execution Vulnerability': '泛微 e-cology OA / 用友 NC BshServlet 远程代码执行漏洞',
    'Smartbi Windowunloading Remote Code Execution Vulnerability': 'Smartbi Windowunloading 远程代码执行漏洞',
    'eYou Mail System Remote Command Execution Vulnerability': '亿邮邮件系统远程命令执行漏洞',
    'Landray OA CVE-2022-34924 Code Execution Vulnerability': '蓝凌 OA CVE-2022-34924 代码执行漏洞',
    'Likeshop formImage Aribitrary File Upload Vulnerability': 'Likeshop 任意文件上传漏洞',
    'Inspur ClusterEngine sysShell Remote Code Execution Vulnerability': '浪潮 ClusterEngine 远程代码执行漏洞',
    'Adobe ColdFusion file_name Arbitrary File Read Vulnerability': 'Adobe ColdFusion 任意文件读取漏洞',
    'Oracle Java Debug Wire Protocol Remote Debugging': 'Oracle Java 调试协议远程调试',
    'HTTP Unix Shell IFS Remote Code Execution Vulnerability': 'HTTP Unix Shell IFS 远程代码执行漏洞',
    'Grafana Labs Grafana Plugin Directory Traversal': 'Grafana 插件目录穿越漏洞',
    'Dahua Smart IoT Management Platform justForTest Information Disclosure Vulnerability': '大华智能 IoT 平台信息泄露漏洞',
    'Binance Domain: www.binance.com': '币安域名访问 (www.binance.com)',
    'Information Disclosure Attempt - Access .git/.svn Directory': '信息泄露尝试 - 访问 .git/.svn 目录',
    'Information Disclosure: Access Temporary File': '信息泄露 - 访问临时文件',
    'Information Disclosure Attempt - Access Linux Sensitive File': '信息泄露尝试 - 访问 Linux 敏感文件',
    'Information Disclosure: Access Linux System File - bash_profile': '信息泄露 - 访问 Linux 系统文件 (bash_profile)',
    'Information Disclosure: Access Linux System File - bashrc': '信息泄露 - 访问 Linux 系统文件 (bashrc)',
    'Information Disclosure Attempt 8 - Access System Sensitive File in URI': '信息泄露尝试 - URI 中访问系统敏感文件',
    'Information Disclosure: Access Linux System File - bash_history': '信息泄露 - 访问 Linux 系统文件 (bash_history)',
    'Directory Traversal Attempt -  Found in HTTP URL': '目录穿越尝试 (HTTP URL)',
    "Directory Traversal Attempt - Special char ';'": "目录穿越尝试 (特殊字符 ';')",
    'Sensitive File Access: phpinfo.php': '敏感文件访问: phpinfo.php',
    'Sensitive File Download Behavior': '敏感文件下载行为',
    'Sensitive File Access: .sql': '敏感文件访问: .sql',
    'Sensitive File Download Behavior -- id_dsa': '敏感文件下载 (id_dsa)',
    'Sensitive Files Read -  Found in HTTP URI': '敏感文件读取 (HTTP URI)',
    'Access Sensitive File: .sql': '访问敏感文件: .sql',
    'Access Sensitive System Path: /proc/self/': '访问敏感系统路径: /proc/self/',
    'OS Command Injection - Found in HTTP Request Parameter': 'OS 命令注入 (HTTP 请求参数)',
    'OS Command Injection - Found in HTTP Header': 'OS 命令注入 (HTTP 头)',
    'Code Injection Attempt - Found in HTTP Request Parameter': '代码注入尝试 (HTTP 请求参数)',
    'HTTP Multipart File Upload - PHP Script': 'HTTP Multipart 文件上传 (PHP 脚本)',
    'HTTP Multipart File Upload - JSP/JSPX Script': 'HTTP Multipart 文件上传 (JSP/JSPX 脚本)',
    'HTTP File Upload - PHP Script': 'HTTP 文件上传 (PHP 脚本)',
    'File Downloading and Command Execution Detected - wget/curl': '文件下载与命令执行 (wget/curl)',
    'Webshell Access Attempt: shell script': 'WebShell 访问尝试: shell 脚本',
    'Authentication Bypass Attempt - Found in HTTP URI': '身份验证绕过尝试 (HTTP URI)'
  };

  // 模式兜底：精确表未命中时，按通用攻击类别词翻译（保留 CVE 编号与产品名）
  var ET_RULES = [
    [/(Remote Code Execution|Remote Command Execution)/gi, '远程代码执行'],
    [/Command Execution/gi, '命令执行'],
    [/(OS )?Command Injection/gi, '命令注入'],
    [/Code Injection/gi, '代码注入'],
    [/(Code Execution)/gi, '代码执行'],
    [/(Directory|Path) Traversal/gi, '目录穿越'],
    [/Information Disclosure/gi, '信息泄露'],
    [/Sensitive File Access/gi, '敏感文件访问'],
    [/Sensitive File Read/gi, '敏感文件读取'],
    [/Sensitive File Download/gi, '敏感文件下载'],
    [/Arbitrary File Upload/gi, '任意文件上传'],
    [/Arbitrary File Read/gi, '任意文件读取'],
    [/File Upload/gi, '文件上传'],
    [/SQL Injection/gi, 'SQL 注入'],
    [/Webshell/gi, 'WebShell'],
    [/Scanner|Scanning|Scan Traffic|Scan Network/gi, '扫描'],
    [/Botnet/gi, '僵尸网络'],
    [/Worm/gi, '蠕虫'],
    [/Malware/gi, '恶意软件'],
    [/Unauthorized Access/gi, '未授权访问'],
    [/Privilege Escalation/gi, '权限提升'],
    [/Authentication Bypass/gi, '身份验证绕过'],
    [/Vulnerability/gi, '漏洞'],
    [/Exploit/gi, '漏洞利用'],
    [/Brute/gi, '暴力破解'],
    // 国产品牌 / OA 产品名
    [/zhiyuan|Seeyon/gi, '致远'],
    [/yonyou/gi, '用友'],
    [/Weaver/gi, '泛微'],
    [/TongDa|TONGDA/gi, '通达'],
    [/Ruijie/gi, '锐捷'],
    [/Sangfor/gi, '深信服'],
    [/Dahua/gi, '大华'],
    [/Hikvision/gi, '海康威视'],
    [/Inspur/gi, '浪潮'],
    [/Landray/gi, '蓝凌'],
    [/Fanruan/gi, '帆软'],
    [/Chanjet/gi, '畅捷通'],
    [/WanHu/gi, '万户'],
    [/Topsec/gi, '天融信'],
    // 攻击类别 / 组件词
    [/Web Backdoor/gi, 'Web后门'],
    [/Tiny Webshell/gi, '微型WebShell'],
    [/Expression Language Injection/gi, 'EL表达式注入'],
    [/Insecure Deserialization/gi, '不安全反序列化'],
    [/Arbitrary File Write/gi, '任意文件写入'],
    [/Arbitrary User Login/gi, '任意用户登录'],
    [/Access Bypass/gi, '访问绕过'],
    [/Shell Access/gi, 'Shell访问'],
    [/IP Camera/gi, 'IP摄像机'],
    [/Intercom Broadcasting System/gi, '可视对讲广播系统'],
    [/Integrated Security Management Platform/gi, '综合安防管理平台'],
    [/Smart Zone Management Platform/gi, '智能区域管理平台'],
    [/Smart IoT Management Platform/gi, '智能IoT平台'],
    [/CAS Platform/gi, 'CAS平台'],
    [/Application Delivery/gi, '应用交付'],
    [/Remote Command Injection/gi, '远程命令注入']
  ];
  function eventTypeText(raw) {
    if (!raw) return '(未知攻击类型)';
    if (ET_EXACT[raw]) return ET_EXACT[raw];
    var t = raw;
    for (var i = 0; i < ET_RULES.length; i++) {
      t = t.replace(ET_RULES[i][0], ET_RULES[i][1]);
    }
    return t;
  }

  // 原始攻击日志：按接口真实返回字段动态渲染（字段名以容器内 WafAttackLog 为准）
  var LOG_LABELS = {
    log_time: '时间', src_ip: '源IP', dst_ip: '目的IP', src_port: '源端口', dst_port: '目的端口',
    severity: '级别', event_type: '攻击类型', action: '处置', device_type: '来源',
    // 长文本字段（触发按词断行 + 列宽处理）
    raw: '原始报文', message: '报文', msg: '原始报文',
    policy: '策略', risk: '风险', url: 'URL',
    country: '国家', province: '省', city: '市',
    id: 'ID', status: '状态',
    // 容器实测兜底（防火墙/WAF 实际模型里偶有带前缀的字段）
    on_id: '序号', msg_id: '报文ID', attack_id: '攻击ID', device_id: '设备ID',
    host: '主机', service: '服务', proto: '协议',
    attack_type: '攻击类型', alert_level: '告警级别',
    src_country: '源地区', dst_country: '目的地区',
    level: '级别'
  };
  var LOG_ORDER = ['log_time', 'src_ip', 'src_port', 'dst_ip', 'dst_port',
                   'severity', 'event_type', 'action', 'device_type', 'raw', 'msg'];

  function fetchJson(url, opts) {
    var o = opts || {};
    o.credentials = 'include';
    o.headers = o.headers || {};
    o.headers['X-Requested-With'] = 'XMLHttpRequest';
    if (o.body) o.headers['Content-Type'] = 'application/json';
    return fetch(url, o).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    });
  }

  function boolVal(v, dft) { return v === undefined || v === null ? dft : !!v; }
  function intVal(v, dft) { var n = parseInt(v, 10); return isNaN(n) ? dft : n; }

  new Vue({
    el: '#app',
    data: {
      rule: {
        severity_threshold: 'high',
        window_minutes: 60,
        enabled: true,
        scan_interval_minutes: 60,
        cooldown_minutes: 60,
        resolve_after_minutes: 120,
        notify_on_resolve: true,
        include_unknown_severity: false,
        dingtalk_enabled: false,
        dingtalk_webhook: '',
        email_enabled: false,
        email_to: '',
        email_subject_prefix: '[eSight安全告警]',
      },
      stats: { firing: 0, acked: 0, resolved: 0, suppressed: 0, total: 0 },
      events: [],
      records: [],
      latest: null,
      total: 0,
      page: 1,
      pageSize: 20,
      filter: { status: '', source: '', keyword: '' },
      drawerVisible: false,
      detailLoading: false,
      detailEvent: null,
      detailLogs: { results: [], total: 0, page: 1, page_size: 20 },
      detailJump: null,
      detailFp: '',
      detailPage: 1,
      scanning: false,
      saving: false,
      msg: '',
      msgCls: 'ok',
    },
    methods: {
      statusText: function (s) { return STATUS_TEXT[s] || s; },
      eventTypeText: function (raw) { return eventTypeText(raw); },
      severityText: function (s) { return severityText(s); },
      sourceText: function (s) { return sourceText(s); },

      showMsg: function (text, isErr) {
        var self = this;
        self.msg = text;
        self.msgCls = isErr ? 'err' : 'ok';
        setTimeout(function () { if (self.msg === text) self.msg = ''; }, 5000);
      },

      // 点击统计卡 → 联动列表筛选（再次点同一卡则清空，回到全部）
      filterByStatus: function (st) {
        var self = this;
        self.filter.status = (self.filter.status === st) ? '' : st;
        self.loadEvents(1);
        // 卡片联动后自动滚动到事件列表，让用户马上看到结果
        var anchor = document.querySelector('.sa-card');
        if (anchor) anchor.scrollIntoView({ behavior: 'smooth', block: 'start' });
      },

      refreshAll: function () {
        this.loadRule();
        this.loadEvents(1);
        this.loadRecords();
        this.loadStats();
      },

      loadRule: function () {
        var self = this;
        return fetchJson(API.rule).then(function (d) {
          self.rule = {
            severity_threshold: d.severity_threshold || 'high',
            window_minutes: intVal(d.window_minutes, 60),
            enabled: boolVal(d.enabled, true),
            scan_interval_minutes: intVal(d.scan_interval_minutes, 60),
            cooldown_minutes: intVal(d.cooldown_minutes, 60),
            resolve_after_minutes: intVal(d.resolve_after_minutes, 120),
            notify_on_resolve: boolVal(d.notify_on_resolve, true),
            include_unknown_severity: boolVal(d.include_unknown_severity, false),
            dingtalk_enabled: boolVal(d.dingtalk_enabled, false),
            dingtalk_webhook: d.dingtalk_webhook || '',
            email_enabled: boolVal(d.email_enabled, false),
            email_to: d.email_to || '',
            email_subject_prefix: d.email_subject_prefix || '[eSight安全告警]',
          };
        }).catch(function (e) { console.warn('loadRule failed', e); });
      },

      loadStats: function () {
        var self = this;
        return fetchJson(API.stats).then(function (d) {
          self.stats = {
            firing: d.firing || 0, acked: d.acked || 0,
            resolved: d.resolved || 0, suppressed: d.suppressed || 0,
            total: d.total || 0
          };
        }).catch(function (e) { console.warn('loadStats failed', e); });
      },

      loadEvents: function (page) {
        var self = this;
        self.page = page || 1;
        var qs = 'page=' + self.page + '&page_size=' + self.pageSize;
        if (self.filter.status) qs += '&status=' + encodeURIComponent(self.filter.status);
        if (self.filter.source) qs += '&source=' + encodeURIComponent(self.filter.source);
        if (self.filter.keyword) qs += '&keyword=' + encodeURIComponent(self.filter.keyword);
        return fetchJson(API.events + '?' + qs).then(function (d) {
          self.events = d.results || [];
          self.total = d.total || 0;
          if (d.stats) self.stats = d.stats;
        }).catch(function (e) { console.warn('loadEvents failed', e); });
      },

      loadRecords: function () {
        var self = this;
        return fetchJson(API.records).then(function (d) {
          var rs = d.results || [];
          self.records = rs.slice(0, 20);
          if (rs.length) self.latest = rs[0];
        }).catch(function (e) { console.warn('loadRecords failed', e); });
      },

      saveRule: function () {
        var self = this;
        self.saving = true;
        fetchJson(API.rule, { method: 'POST', body: JSON.stringify(self.rule) })
          .then(function (d) {
            self.loadRule();
            self.showMsg('规则已保存');
          })
          .catch(function (e) { self.showMsg('保存失败：' + e.message, true); })
          .then(function () { self.saving = false; });
      },

      scan: function () {
        var self = this;
        self.scanning = true;
        fetchJson(API.scan, { method: 'POST' })
          .then(function (d) {
            if (d.ok) {
              self.latest = d.record;
              self.loadRecords();
              self.loadEvents(1);
              self.loadStats();
              var r = d.record;
              self.showMsg('检测完成：新增 ' + r.events_new + ' / 复现 ' + r.events_recurred +
                ' / 冷却抑制 ' + r.events_suppressed + ' / 恢复 ' + r.events_resolved);
            } else {
              self.showMsg('检测失败：' + (d.error || '未知错误'), true);
            }
          })
          .catch(function (e) { self.showMsg('检测失败：' + e.message, true); })
          .then(function () { self.scanning = false; });
      },

      act: function (e, action) {
        var self = this;
        var note = '';
        if (action === 'ack' || action === 'suppress') {
          note = window.prompt('处理备注（可留空）', '') || '';
        }
        fetchJson(API.action, {
          method: 'POST',
          body: JSON.stringify({ fingerprint: e.fingerprint, action: action, note: note })
        }).then(function (d) {
          if (d.ok) {
            self.loadEvents(self.page);
            self.loadStats();
            self.showMsg('操作成功：' + self.statusText(d.event.status));
          } else {
            self.showMsg('操作失败：' + (d.error || '未知错误'), true);
          }
        }).catch(function (er) { self.showMsg('操作失败：' + er.message, true); });
      },

      // ---- 事件详情钻取 ----
      openDetail: function (e) {
        var self = this;
        self.detailFp = e.fingerprint;
        self.detailEvent = null;
        self.detailLogs = { results: [], total: 0, page: 1, page_size: 20 };
        self.detailJump = null;
        self.detailPage = 1;
        self.drawerVisible = true;
        self.detailLoading = true;
        fetchJson(API.detail + '?fingerprint=' + encodeURIComponent(e.fingerprint))
          .then(function (d) {
            if (d.ok) {
              self.detailEvent = d.event;
              self.detailLogs = d.logs;
              self.detailJump = d.jump;
            } else {
              self.showMsg('详情加载失败：' + (d.error || '未知错误'), true);
            }
          })
          .catch(function (er) { self.showMsg('详情加载失败：' + er.message, true); })
          .then(function () { self.detailLoading = false; });
      },
      closeDetail: function () { this.drawerVisible = false; },
      detailChangePage: function (p) {
        var self = this;
        if (!self.detailFp || p < 1) return;
        // 修复前守卫：p > detailPage && p*page_size >= total 永远拦截「末页」
        // （末页 L=ceil(total/page_size) 必满足 L*page_size>=total），导致末页永远打不开。
        // 改为只拦截越界页：p 超出总页数时才 return。
        if (p > self.detailTotalPages()) return;
        self.detailPage = p;
        self.detailLoading = true;
        fetchJson(API.detail + '?fingerprint=' + encodeURIComponent(self.detailFp) + '&page=' + p)
          .then(function (d) {
            if (d.ok) { self.detailLogs = d.logs; }
            else { self.showMsg('详情加载失败：' + (d.error || ''), true); }
          })
          .catch(function (er) { self.showMsg('详情加载失败：' + er.message, true); })
          .then(function () { self.detailLoading = false; });
      },
      detailTotalPages: function () {
        if (!this.detailLogs || !this.detailLogs.total) return 1;
        return Math.ceil(this.detailLogs.total / this.detailLogs.page_size) || 1;
      },
      logVal: function (log, key) {
        var v = log[key];
        if (v === undefined || v === null || v === '') return '-';
        return v;
      },
      // 动态列：取所有原始日志行的字段并集，按 LOG_ORDER 优先排序
      logColumns: function () {
        var seen = {}, keys = [];
        var rows = this.detailLogs.results || [];
        for (var i = 0; i < rows.length; i++) {
          for (var k in rows[i]) {
            if (!seen[k]) { seen[k] = 1; keys.push(k); }
          }
        }
        keys.sort(function (a, b) {
          var ia = LOG_ORDER.indexOf(a), ib = LOG_ORDER.indexOf(b);
          if (ia < 0) ia = 999; if (ib < 0) ib = 999;
          return ia - ib;
        });
        return keys;
      },
      logLabel: function (k) { return LOG_LABELS[k] || k; },
      logCellClass: function (k) {
        // 长文本字段触发按词断行 + 列宽（max-width: 640px）、保留空格/标点
        if (k === 'raw' || k === 'message' || k === 'msg') return 'sa-mono sa-msg-col';
        if (k === 'event_type' || k === 'severity') return '';
        return 'sa-mono';
      },
      logCell: function (log, k) {
        var v = log[k];
        if (v === undefined || v === null || v === '') return '-';
        if (k === 'severity') return this.severityText(v);
        if (k === 'event_type') return this.eventTypeText(v);
        return String(v);
      },
    },
    mounted: function () { this.refreshAll(); },
  });
})();
