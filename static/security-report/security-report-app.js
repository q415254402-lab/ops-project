// -*- coding: utf-8 -*-
// 安全报表 SPA（Vue 2，复用 ../host-monitor/lib/vue.min.js）
// 调用 /t/esight/api/v1/cmdb/security/report/ 三个端点：
//   list    /?period_type=           -> 历史归档列表
//   current /current/?period_type=   -> 实时当前周期（含 modules + compare 环比）
//   detail  /<type>/<key>/           -> 归档详情（data 内为 build_report 全量，含 modules + compare）
(function () {
  var BASE = '/t/esight/api/v1/cmdb/security/report';

  function api(path) {
    return fetch(BASE + path, { credentials: 'include' })
      .then(function (r) { return r.json(); })
      .then(function (j) {
        if (!j || j.code !== 200) throw new Error((j && j.message) || '接口返回异常');
        return j.data;
      });
  }

  // 各模块展示配置
  var MODULE_DEFS = [
    { key: 'waf',   name: 'WAF 攻击',   totals: [{ k: 'total', label: '攻击总数' }, { k: 'high', label: '高危' }], topKey: 'top_src_ip', topLabel: 'TOP 攻击源 IP', link: '/security/wafMonitor' },
    { key: 'fw',    name: '防火墙',      totals: [{ k: 'total', label: '拦截总数' }, { k: 'high', label: '高危' }], topKey: 'top_src_ip', topLabel: 'TOP 来源 IP',   link: '/security/fwMonitor' },
    { key: 'vuln',  name: '漏洞扫描',    totals: [{ k: 'total', label: '漏洞总数' }, { k: 'high', label: '高危漏洞' }], topKey: 'top_vulns', topLabel: 'TOP 漏洞',       link: '/security/vscanMonitor' },
    { key: 'alert', name: '安全告警',    totals: [{ k: 'total', label: '扫描次数' }, { k: 'scans_with_event', label: '有事件' }], topKey: null, topLabel: '', link: '/security/securityAlert' },
    { key: 'host',  name: '主机监控',    totals: [{ k: 'total', label: '主机数' }, { k: 'ssh_error', label: 'SSH异常' }, { k: 'snmp_error', label: 'SNMP异常' }], topKey: 'err_hosts', topLabel: '异常主机', link: '/network/hostMonitor' }
  ];

  var SEV = {
    '信息': ['#fff1f0', '#ffa39e', '#cf1322'],
    '低':   ['#f6ffed', '#b7eb8f', '#389e0d'],
    '中':   ['#fffbe6', '#ffe58f', '#d48806'],
    '高':   ['#fff1f0', '#ffa39e', '#cf1322'],
    '严重': ['#fff0f6', '#ffadd2', '#c41d7f'],
    '默认': ['#e6f7ff', '#91d5ff', '#1890ff']
  };

  // 走势图取的归档份数（不含"实时"那一点）：日 13+1=14 期 / 周 7+1=8 期 / 月 11+1=12 期
  var TREND_SPAN = { day: 13, week: 7, month: 11 };

  new Vue({
    el: '#app',
    data: {
      tabs: [{ key: 'day', label: '日报' }, { key: 'week', label: '周报' }, { key: 'month', label: '月报' }],
      moduleDefs: MODULE_DEFS,
      pt: 'day',
      loading: false,
      msg: '',
      msgCls: '',
      reports: [],
      visibleCount: 20,
      currentView: null,
      selectedKey: null,
      view: null
    },
    computed: {
      liveRangeText: function () {
        if (this.pt === 'day') return '今日';
        if (this.pt === 'week') return '本周至今';
        return '本月至今';
      },
      viewRangeText: function () {
        if (!this.view) return '';
        return this.view.period_start.slice(0, 10) + ' ~ ' + this.view.period_end.slice(0, 10);
      },
      visibleReports: function () {
        return this.reports.slice(0, this.visibleCount);
      },
      // 走势数据：归档 summary（旧→新）+ 末尾追加"实时"点
      trendPoints: function () {
        var span = TREND_SPAN[this.pt] || 13;
        var rows = this.reports.slice(0, span).slice().reverse();  // reports 是新的在前
        var labels = [], waf = [], fw = [];
        for (var i = 0; i < rows.length; i++) {
          var s = rows[i].summary || {};
          labels.push((rows[i].period_start || '').slice(5, 10));
          waf.push(s.waf || 0);
          fw.push(s.fw || 0);
        }
        if (this.currentView) {
          var cm = this.currentView.modules || {};
          var gt = function (m, k) { return ((cm[m] || {}).totals || {})[k] || 0; };
          labels.push(this.pt === 'day' ? '今日' : (this.pt === 'week' ? '本周' : '本月'));
          waf.push(gt('waf', 'total'));
          fw.push(gt('fw', 'total'));
        }
        var max = 0;
        for (var j = 0; j < waf.length; j++) {
          if (waf[j] > max) max = waf[j];
          if (fw[j] > max) max = fw[j];
        }
        return { labels: labels, waf: waf, fw: fw, max: max };
      },
      // 走势图几何：把 trendPoints 映射成 SVG 坐标
      trendGeo: function () {
        var p = this.trendPoints;
        var n = p.labels.length;
        if (n < 2) return null;
        var W = 600, H = 150, PL = 46, PR = 14, PT = 16, PB = 26;
        var iw = W - PL - PR, ih = H - PT - PB;
        var top = p.max > 0 ? p.max : 1;

        function fx(i) { return PL + (iw * i) / (n - 1); }
        function fy(v) { return PT + ih - (ih * v) / top; }

        var wafPts = [], fwPts = [], dots = [];
        for (var i = 0; i < n; i++) {
          var x = fx(i);
          wafPts.push(x.toFixed(1) + ',' + fy(p.waf[i]).toFixed(1));
          fwPts.push(x.toFixed(1) + ',' + fy(p.fw[i]).toFixed(1));
          dots.push({
            i: i, x: x, yw: fy(p.waf[i]), yf: fy(p.fw[i]),
            wv: p.waf[i], fv: p.fw[i],
            // 点多时隔一个显示 x 轴标签，但最后一点必显示
            tick: (n <= 8 || i % 2 === 0 || i === n - 1) ? p.labels[i] : ''
          });
        }
        var grid = [];
        for (var g = 0; g <= 2; g++) {
          var v = (top * g) / 2;
          grid.push({ y: fy(v), label: Math.round(v) });
        }
        return {
          w: W, h: H, pl: PL,
          wafPts: wafPts.join(' '), fwPts: fwPts.join(' '),
          dots: dots, grid: grid,
          last: dots.length ? dots[dots.length - 1] : null
        };
      }
    },
    methods: {
      fmt: function (n) {
        if (n === null || n === undefined) return '—';
        return Number(n).toLocaleString('en-US');
      },
      moduleTotals: function (key) {
        var m = (this.view && this.view.modules && this.view.modules[key]) || {};
        return m.totals || {};
      },
      // 模块元信息（如 host 的 snapshot 标记）
      moduleMeta: function (key) {
        var m = (this.view && this.view.modules && this.view.modules[key]) || {};
        return m.meta || {};
      },
      // 返回 {dir, pctText} 或 null
      // 2026-09-04 修正：0→0 不显示环比；上期为 0 且本期 >0 才标 NEW；持平显示「持平」而非 ▲0%
      cmp: function (key, k) {
        var c = this.view && this.view.compare && this.view.compare[key] && this.view.compare[key][k];
        if (!c) return null;
        var cur = c.cur || 0, prev = c.prev || 0;
        if (cur === 0 && prev === 0) return null;          // 两期皆 0，环比无意义
        if (prev === 0) return { dir: 'up', pctText: 'NEW' }; // 上期无、本期有
        if (c.delta === 0) return { dir: 'flat', pctText: '持平' };
        return { dir: c.delta > 0 ? 'up' : 'down', pctText: Math.abs(c.pct) + '%' };
      },
      // ── 本期总结展示辅助 ──
      riskLabel: function (lv) {
        var m = { '高': '高风险', '中': '中风险', '低': '低风险' };
        return m[lv] || '风险定级';
      },
      riskClass: function (lv) {
        var m = { '高': 'high', '中': 'mid', '低': 'low' };
        return m[lv] || 'unknown';
      },
      engineLabel: function (s) {
        if (s.engine === 'ai') return 'AI 生成 · ' + (s.model || '');
        if (s.engine === 'rule') return '规则引擎';
        return '';
      },
      sevList: function (key) {
        if (!this.view) return [];
        var mod = this.view.modules[key] || {};
        var arr = mod.severity_dist || mod.monitor_dist || [];
        return arr.filter(function (s) { return s.value > 0; }).map(function (s) {
          var pal = SEV[s.name] || SEV['默认'];
          return { name: s.name, value: s.value, bg: pal[0], bd: pal[1], fg: pal[2] };
        });
      },
      topList: function (key) {
        if (!this.view) return [];
        var mod = this.view.modules[key] || {};
        var def = null;
        for (var i = 0; i < this.moduleDefs.length; i++) if (this.moduleDefs[i].key === key) def = this.moduleDefs[i];
        var arr = (def && def.topKey) ? (mod[def.topKey] || []) : [];
        return arr.slice(0, 5);
      },
      switchPt: function (pt) {
        var self = this;
        self.pt = pt;
        self.selectedKey = null;
        self.view = null;
        self.visibleCount = 20;
        self.loading = true;
        self.msg = '';
        Promise.all([self.loadCurrent(pt), self.loadList(pt)]).then(function () {
          self.loading = false;
        }).catch(function (e) {
          self.loading = false;
          self.msg = '加载失败：' + (e && e.message ? e.message : e);
          self.msgCls = 'err';
        });
      },
      loadCurrent: function (pt) {
        var self = this;
        return api('/current/?period_type=' + pt).then(function (d) {
          self.currentView = {
            archived: false,
            period_start: d.period_start, period_end: d.period_end,
            modules: d.modules, compare: d.compare,
            summary: d.summary
          };
          if (!self.selectedKey) self.view = self.currentView;
        });
      },
      loadList: function (pt) {
        var self = this;
        return api('/?period_type=' + pt).then(function (d) {
          self.reports = d.list || [];
        });
      },
      showCurrent: function () {
        this.selectedKey = null;
        if (this.currentView) this.view = this.currentView;
        else this.switchPt(this.pt);
      },
      openReport: function (r) {
        var self = this;
        self.selectedKey = r.period_key;
        self.msg = '';
        api('/' + r.period_type + '/' + r.period_key + '/').then(function (outer) {
          var inner = outer.data || {};
          self.view = {
            archived: true,
            period_start: inner.period_start, period_end: inner.period_end,
            modules: inner.modules, compare: inner.compare,
            summary: outer.summary,
            key: outer.period_key, title: outer.title
          };
        }).catch(function (e) {
          self.msg = '加载归档详情失败：' + (e && e.message ? e.message : e);
          self.msgCls = 'err';
        });
      }
    },
    mounted: function () {
      this.switchPt('day');
    }
  });
})();
