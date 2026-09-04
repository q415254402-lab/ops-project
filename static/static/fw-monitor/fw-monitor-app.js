// eSight 网络安全设备监控 - WAF 攻击日志大屏
// 数据源：eSight 后端 /waf/stats/ + /waf/logs/（LAS syslog 转发落库）
(function () {
  'use strict';
  var API = {
    stats: '/t/esight/api/v1/cmdb/waf/stats/',
    logs: '/t/esight/api/v1/cmdb/waf/logs/',
    logsExport: '/t/esight/api/v1/cmdb/waf/logs/export/',
  };

  function fetchJson(url, opts) {
    var o = opts || {};
    o.credentials = 'include';
    o.headers = o.headers || {};
    o.headers['X-Requested-With'] = 'XMLHttpRequest';
    return fetch(url, o).then(function (r) { return r.json(); });
  }

  var app = new Vue({
    el: '#app',
    data: function () {
      return {
        loading: true,
        range: '24h',
        ranges: [{ v: '24h', t: '近24小时' }, { v: '3d', t: '近3天' }, { v: '7d', t: '近7天' }, { v: 'custom', t: '自定义' }],
        customStart: '',
        customEnd: '',
        stats: { total: 0, high_cnt: 0, src_ip_cnt: 0, dst_ip_cnt: 0 },
        typeDist: [],
        srcTop: [],
        trend: {},
        logs: [],
        chartsInited: false,
        chartInstances: {},
        _timer: null,
        // 2026-08-17：统计卡下钻
        view: 'dash',
        detailType: 'total',
        detailLogs: [],
        detailIpList: [],
        detailLoading: false,
        detailTotal: 0,
        _detailFilterIp: '',
        _detailField: 'src_ip',
        drawerLog: null,
      };
    },
    mounted: function () {
      this.loadAll();
      var self = this;
      this._timer = setInterval(function () { self.loadAll(); }, 30000);
      window.addEventListener('beforeunload', function () { clearInterval(self._timer); });
      window.addEventListener('resize', function () {
        Object.keys(self.chartInstances).forEach(function (k) {
          if (self.chartInstances[k]) self.chartInstances[k].resize();
        });
      });
      // 2026-08-17：Esc 键关闭抽屉
      window.addEventListener('keydown', function (e) {
        if (e.key === 'Escape' && self.drawerLog) { self.closeDrawer(); }
      });
      // 2026-08-18：点击抽屉外部关闭（替代灰色蒙层）
      window.addEventListener('click', function (e) {
        if (!self.drawerLog) return;
        var d = document.querySelector('.waf-drawer');
        if (d && !d.contains(e.target)) { self.closeDrawer(); }
      });
      // 2026-08-17：v-if="loading" 切换 + watch 时序不稳定——多轮兜底 init
      setTimeout(function () { self._tryInitCharts(); }, 100);
      setTimeout(function () { self._tryInitCharts(); }, 600);
    },
    updated: function () {
      this._tryInitCharts();
    },
    watch: {
      loading: function (v) {
        if (!v) this.$nextTick(this._tryInitCharts);
      },
      typeDist: function () { if (this.chartsInited) this._updateCharts(); },
      srcTop: function () { if (this.chartsInited) this._updateCharts(); },
      trend: function () { if (this.chartsInited) this._updateCharts(); },
      // 2026-08-17：detail → dash 时图表 DOM 被 v-if 卸载重建，必须 dispose + 重 init
      view: function (v) {
        var self = this;
        if (v === 'dash') {
          Object.keys(self.chartInstances).forEach(function (k) {
            if (self.chartInstances[k]) { try { self.chartInstances[k].dispose(); } catch (e) {} }
          });
          self.chartInstances = {};
          self.chartsInited = false;
          setTimeout(function () { self._tryInitCharts(); }, 100);
          setTimeout(function () { self._tryInitCharts(); }, 400);
        }
      },
    },
    computed: {
      detailTitle: function () {
        var ip = this._detailFilterIp;
        switch (this.detailType) {
          case 'total': return '全部攻击日志';
          case 'high': return '高危攻击日志';
          case 'src': return '攻击源 IP 列表';
          case 'dst': return '被攻击目标列表';
          case 'ip': return 'IP 攻击记录 - ' + ip;
          default: return '攻击日志';
        }
      },
    },
    methods: {
      setRange: function (r) {
        if (r === 'custom') {
          if (!this.customStart || !this.customEnd) {
            var nd = new Date();
            var pd = new Date(Date.now() - 24 * 3600 * 1000);
            this.customStart = this.toLocalInput(pd);
            this.customEnd = this.toLocalInput(nd);
          }
          this.range = 'custom';
          this.loadAll();
          return;
        }
        this.range = r;
        this.loadAll();
      },
      // 2026-08-27：自定义时间段辅助
      toLocalInput: function (d) {
        function p(x) { return (x < 10 ? '0' : '') + x; }
        return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + 'T' + p(d.getHours()) + ':' + p(d.getMinutes());
      },
      fmtDt: function (s) {
        if (!s) return '';
        s = String(s).replace('T', ' ');
        if (s.length === 16) s += ':00';
        return s;
      },
      rangeParams: function () {
        if (this.range === 'custom') {
          var q = '';
          var s = this.fmtDt(this.customStart);
          var e = this.fmtDt(this.customEnd);
          if (s) q += 'start=' + encodeURIComponent(s);
          if (e) { if (q) q += '&'; q += 'end=' + encodeURIComponent(e); }
          return q;
        }
        return 'range=' + this.range;
      },
      applyCustom: function () {
        if (!this.customStart || !this.customEnd) return;
        this.range = 'custom';
        this.loadAll();
      },
      // 2026-08-17：统计卡下钻（2026-08-18：分页 + 总数）
      openCard: function (type) {
        var self = this;
        self.view = 'detail';
        self.detailType = type;
        self._detailFilterIp = '';
        self.detailLoading = true;
        self.detailLogs = [];
        self.detailIpList = [];
        self.detailTotal = 0;
        if (type === 'src' || type === 'dst') {
          fetchJson(API.stats + '?' + self.rangeParams() + '&device_type=Firewall')
            .then(function (res) {
              var st = (res && res.data) || {};
              self.detailIpList = (type === 'src' ? (st.src_top || []) : (st.dst_top || [])).map(function (s) {
                return { ip: s.src_ip || s.dst_ip, cnt: s.c, high: s.high || 0, last: s.last || '' };
              });
              self.detailTotal = type === 'src' ? (st.src_ip_cnt || 0) : (st.dst_ip_cnt || 0);
              self.detailLoading = false;
            })
            .catch(function () { self.detailLoading = false; });
        } else {
          var q = '?' + self.rangeParams() + '&limit=200&offset=0&device_type=Firewall';
          if (type === 'high') q += '&severity=high';
          fetchJson(API.logs + q)
            .then(function (res) {
              self.detailTotal = ((res && res.data) || {}).total || 0;
              self.detailLogs = ((res && res.data && res.data.data) || []);
              self.detailLoading = false;
            })
            .catch(function () { self.detailLoading = false; });
        }
      },
      loadMore: function () {
        var self = this;
        if (self.detailLoading || !self.detailLogs.length) return;
        self.detailLoading = true;
        var q = '?' + self.rangeParams() + '&limit=200&offset=' + self.detailLogs.length + '&device_type=Firewall';
        if (self.detailType === 'high') q += '&severity=high';
        if (self.detailType === 'ip' && self._detailFilterIp && self._detailField) {
          q += '&' + self._detailField + '=' + encodeURIComponent(self._detailFilterIp);
        }
        fetchJson(API.logs + q)
          .then(function (res) {
            var arr = ((res && res.data && res.data.data) || []);
            self.detailLogs = self.detailLogs.concat(arr);
            self.detailTotal = ((res && res.data) || {}).total || self.detailTotal;
            self.detailLoading = false;
          })
          .catch(function () { self.detailLoading = false; });
      },
      filterByIp: function (ip) {
        var self = this;
        var origType = self.detailType;
        self.detailType = 'ip';
        self._detailFilterIp = ip;
        self._detailField = origType === 'src' ? 'src_ip' : 'dst_ip';
        self.detailLoading = true;
        self.detailTotal = 0;
        var f = self._detailField;
        fetchJson(API.logs + '?' + self.rangeParams() + '&limit=200&offset=0&device_type=Firewall&' + f + '=' + encodeURIComponent(ip))
          .then(function (res) {
            self.detailTotal = ((res && res.data) || {}).total || 0;
            self.detailLogs = ((res && res.data && res.data.data) || []);
            self.detailLoading = false;
          })
          .catch(function () { self.detailLoading = false; });
      },
      backDash: function () {
        this.view = 'dash';
      },
      openLog: function (l) {
        this.drawerLog = l;
      },
      closeDrawer: function () {
        this.drawerLog = null;
      },
      _sinceHours: function () {
        if (this.range === '7d') return 168;
        if (this.range === '3d') return 72;
        if (this.range === 'custom') {
          var s = this.fmtDt(this.customStart), e = this.fmtDt(this.customEnd);
          if (s && e) {
            var a = new Date(s.replace(/-/g, '/')), b = new Date(e.replace(/-/g, '/'));
            if (!isNaN(a) && !isNaN(b)) return Math.max(1, Math.round((b - a) / 3600000));
          }
          return 24;
        }
        return 24;
      },
      sevCls: function (s) {
        if (!s) return 'low';
        if (s.indexOf('高') >= 0 || s.indexOf('high') >= 0 || s.indexOf('严重') >= 0 || s.indexOf('crit') >= 0) return 'high';
        if (s.indexOf('中') >= 0 || s.indexOf('medium') >= 0) return 'mid';
        return 'low';
      },
      // 2026-08-17：等级/动作/攻击类型英文转中文（展示层映射，不破坏原始数据）
      sevText: function (s) {
        var m = { high: '高', medium: '中', low: '低', critical: '严重', info: '信息', alert: '告警', emergency: '紧急' };
        var k = String(s || '').toLowerCase();
        return m[k] || s || '-';
      },
      actText: function (a) {
        var m = { block: '阻断', deny: '拒绝', allow: '允许', permit: '允许', alert: '告警', drop: '丢弃', reset: '重置', log: '记录', pass: '放行' };
        var k = String(a || '').toLowerCase();
        return m[k] || a || '-';
      },
      typeText: function (t) {
        var s = String(t || '');
        if (!s) return '-';
        var low = s.toLowerCase();
        // 攻击大类 → 中文（保留原始签名/名称便于识别）
        if (low.indexOf('worm') >= 0) return '蠕虫攻击（' + s + '）';
        if (low.indexOf('dlp') >= 0) return '数据防泄漏';
        if (low.indexOf('sql') >= 0) return 'SQL注入';
        if (low.indexOf('xss') >= 0) return 'XSS跨站脚本';
        if (low.indexOf('command') >= 0 || low.indexOf('cmd') >= 0) return '命令注入';
        if (low.indexOf('csrf') >= 0) return 'CSRF跨站请求伪造';
        if (low.indexOf('brute') >= 0) return '暴力破解';
        if (low.indexOf('path') >= 0) return '路径穿越';
        if (low.indexOf('file') >= 0 || low.indexOf('upload') >= 0) return '文件上传攻击';
        if (low.indexOf('bot') >= 0 || low.indexOf('spider') >= 0) return '爬虫防护';
        if (low.indexOf('webshell') >= 0) return 'Webshell后门';
        if (low.indexOf('url') >= 0) return 'URL过滤';
        if (low.indexOf('virus') >= 0 || low.indexOf('malware') >= 0) return '病毒木马';
        if (low.indexOf('trojan') >= 0) return '木马攻击';
        if (low.indexOf('exploit') >= 0 || low.indexOf('rce') >= 0) return '远程代码执行';
        if (low.indexOf('ddos') >= 0 || low.indexOf('flood') >= 0) return 'DDoS拒绝服务';
        if (low.indexOf('portscan') >= 0 || low.indexOf('scan') >= 0) return '端口扫描';
        return s;
      },
      openDetail: null,
      _tryInitCharts: function () {
        if (this.chartsInited) return;
        if (!this.$refs.typeChart || !this.$refs.srcChart || !this.$refs.trendChart) return;
        this.chartsInited = true;
        try {
          this.chartInstances.type = echarts.init(this.$refs.typeChart);
          this.chartInstances.src = echarts.init(this.$refs.srcChart);
          this.chartInstances.trend = echarts.init(this.$refs.trendChart);
          this._updateCharts();
        } catch (e) { console.error('echarts init error:', e); }
      },
      _updateCharts: function () {
        if (!this.chartInstances.type) return;
        var self = this;
        var typeDistTop = self.typeDist.slice().sort(function (a, b) { return b.c - a.c; }).slice(0, 10);
        var srcTop10 = self.srcTop.slice(0, 10);
        self.chartInstances.type.setOption({
          tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
          legend: {
            bottom: 0, type: 'scroll', textStyle: { fontSize: 11 },
            // 2026-08-17：图例显示「类型名(数量)」+ 截断长名（避免被横向滚动挡住）
            formatter: function (name) {
              var t = typeDistTop.find(function (x) { return self.typeText(x.event_type) === name; });
              var cnt = t ? t.c : '';
              var short = name.length > 12 ? name.slice(0, 12) + '…' : name;
              return short + ' (' + cnt + ')';
            }
          },
          series: [{
            type: 'pie', radius: ['35%', '65%'], center: ['50%', '42%'],
            data: typeDistTop.map(function (t) { return { name: self.typeText(t.event_type), value: t.c }; }),
            label: { show: false },
          }],
        });
        self.chartInstances.src.setOption({
          tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
          // 2026-08-17：grid.left 加大到 110 容纳完整 IP（"192.168.xx.xx" 12-15 字符不截断）
          grid: { left: 110, right: 20, top: 10, bottom: 30 },
          xAxis: { type: 'value', axisLabel: { fontSize: 10 } },
          yAxis: {
            type: 'category',
            data: srcTop10.map(function (s) { return s.src_ip; }).reverse(),
            axisLabel: { fontSize: 10 },
          },
          series: [{
            type: 'bar', data: srcTop10.map(function (s) { return s.c; }).reverse(),
            itemStyle: { color: '#faad14' }, barMaxWidth: 18,
            label: { show: true, position: 'right', fontSize: 10, color: '#333' },
          }],
        });
        self.chartInstances.trend.setOption({
          tooltip: { trigger: 'axis' },
          grid: { left: 40, right: 15, top: 10, bottom: 30 },
          xAxis: { type: 'category', data: Object.keys(self.trend), axisLabel: { fontSize: 9, rotate: 45 } },
          yAxis: { type: 'value', minInterval: 1, axisLabel: { fontSize: 10 } },
          series: [{ type: 'bar', data: Object.values(self.trend), itemStyle: { color: '#ff4d4f' }, barMaxWidth: 12 }],
        });
      },
      loadAll: function () {
        var self = this;
        Promise.all([
          fetchJson(API.stats + '?' + this.rangeParams() + '&device_type=Firewall'),
          fetchJson(API.logs + '?limit=50&device_type=Firewall'),
        ]).then(function (res) {
          var st = (res[0] && res[0].data) || {};
          self.stats = st;
          self.typeDist = st.type_dist || [];
          self.srcTop = st.src_top || [];
          self.trend = st.trend || {};
          self.logs = ((res[1] && res[1].data && res[1].data.data) || []);
          self.loading = false;
          if (self.chartsInited) self._updateCharts();
        }).catch(function (e) {
          console.error('load error:', e);
          self.loading = false;
        });
      },
      // 2026-08-28：导出当前时间窗日志（CSV，所见即所导）
      exportLogs: function () {
        var q = this.rangeParams() + '&device_type=Firewall';
        window.open(API.logsExport + '?' + q, '_blank');
      },
    },
  });

  window.__fwMonitorApp = app;
})();
