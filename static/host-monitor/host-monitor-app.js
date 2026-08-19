// eSight 主机监控大屏 app
// 数据源：eSight 后端 host-monitor API（转发正式平台 + Zabbix）
(function () {
  'use strict';
  var API = {
    hostList: '/t/esight/api/v1/cmdb/host-monitor/host-list/',
    hostGroups: '/t/esight/api/v1/cmdb/host-monitor/host-groups/',
    realtime: '/t/esight/api/v1/cmdb/host-monitor/zabbix/realtime/',
    alarms: '/t/esight/api/v1/cmdb/host-monitor/zabbix/alarms/',
    config: '/t/esight/api/v1/cmdb/host-monitor/config/',
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
        stats: { total: 0, online: 0, offline: 0, alarmCount: 0, monitored: 0 },
        topHosts: [],
        alarms: [],
        _groups: [],
        _osStat: {},
        _manageStat: { ssh: 0, agent: 0 },
        chartInstancesInited: false,
        chartInstances: {},
        _timer: null,
        // 2026-08-17：统计卡下钻
        view: 'dash',          // dash | hosts | alarms
        hostFilter: 'all',     // all | online | offline
        hostRows: [],
        hostLoading: false,
        // 2026-08-17：主机详情抽屉弹窗（照搬 control 平台抽屉样式：右侧滑出 + iframe 内嵌 CMDB）
        drawerHost: null,
        drawerUrl: '',
        _cmdbBase: null,
      };
    },
    mounted: function () {
      var self = this;
      // 2026-08-17：取 CMDB 基地址（测试环境=正式平台跨域；正式部署配 HOST_MONITOR_CMDB_BASE=/o/cmdb 同域）
      fetchJson(API.config).then(function (res) {
        if (res && res.data && res.data.cmdb_base) self._cmdbBase = res.data.cmdb_base;
      }).catch(function () {});
      this.loadAll();
      this._timer = setInterval(function () { self.loadAll(); }, 30000);
      window.addEventListener('beforeunload', function () { clearInterval(self._timer); });
      window.addEventListener('resize', function () {
        Object.keys(self.chartInstances).forEach(function (k) {
          if (self.chartInstances[k]) self.chartInstances[k].resize();
        });
      });
    },
    updated: function () {
      // 兜底：v-else 区域已挂载后初始化 echarts（避免 updated 触发时机问题）
      this._tryInitCharts();
    },
    watch: {
      loading: function (v) {
        // loading 变 false（v-else 挂载）后 init
        if (!v) this.$nextTick(this._tryInitCharts);
      },
      // 2026-08-17：从 hosts/alarms 视图返回大屏时 DOM 重新挂载，旧 echarts 实例失效 → 重 init
      view: function (v) {
        if (v !== 'dash') return;
        Object.keys(this.chartInstances).forEach(function (k) {
          if (this.chartInstances[k]) try { this.chartInstances[k].dispose(); } catch (e) {}
        }.bind(this));
        this.chartInstances = {};
        this.chartInstancesInited = false;
        this.$nextTick(this._tryInitCharts);
      },
    },
    methods: {
      _tryInitCharts() {
        if (this.chartInstancesInited) return;
        if (!this.$refs.groupChart || !this.$refs.osChart || !this.$refs.manageChart || !this.$refs.alarmTrendChart) return;
        this.chartInstancesInited = true;
        this._initCharts();
      },
      loadAll: function () {
        var self = this;
        Promise.all([
          fetchJson(API.hostList + '?page=1&per_page=200&system_type=all&host_type=all&control_type=all&controller_id=all&agent_state=all&ssh_state=all&search_type=auto_fields&search_data=&group_name=all&monitor_status='),
          fetchJson(API.hostGroups),
          fetchJson(API.alarms + '?type=current&limit=20'),
        ]).then(function (res) {
          // res[0].data = host-list 分页结构 {current,pageSize,total,data:[主机数组],host,ssh,agent,monitor}
          var hostData = (res[0] && res[0].data) || {};
          var hostList = hostData.data || [];
          var groups = (res[1] && res[1].data) || [];
          var alarms = (res[2] && res[2].data) || [];
          self.alarms = alarms;
          self.stats.total = hostData.total || hostList.length;
          // 2026-08-17：在线/离线按监控类型取对应状态（Zabbix→zabbix_agent_state；Prometheus→prom_state；
          // 兜底→zabbix_state 正常）。不能只看 zabbix_agent_state（Prometheus 主机它恒 false → 误判离线）
          var onlineCnt = hostList.filter(function (h) { return self._isOnline(h); }).length;
          self.stats.online = onlineCnt;
          self.stats.offline = (hostData.total || hostList.length) - onlineCnt;
          self.stats.monitored = ((hostData.monitor || {}).normal || 0);
          self.stats.alarmCount = alarms.length;
          // 缓存图表数据
          self._groups = groups;
          self._osStat = hostData.host || {};
          self._manageStat = { ssh: ((hostData.ssh || {}).normal || 0), agent: ((hostData.agent || {}).normal || 0) };
          // 如果图表已 init，更新数据；否则等 updated 钩子
          if (self.chartInstancesInited) {
            self._updateCharts();
          }
          // TOP10 实时值（只取前 15 台避免 Zabbix 批量超时）
          var ips = hostList.map(function (h) { return h.ip; }).filter(Boolean).slice(0, 15);
          self.loadRealtime(ips);
        }).catch(function (e) {
          console.error('host monitor load error:', e);
        }).finally(function () {
          self.loading = false;
        });
      },
      loadRealtime: function (ips) {
        var self = this;
        if (!ips.length) return;
        fetchJson(API.realtime + '?ips=' + encodeURIComponent(ips.join(',')) + '&metrics=cpu_util,mem_util')
          .then(function (res) {
            var rt = (res && res.data) || {};
            var list = [];
            Object.keys(rt).forEach(function (ip) {
              var v = rt[ip] || {};
              list.push({
                ip: ip,
                cpu: parseFloat((v.values || {}).cpu_util || 0),
                mem: parseFloat((v.values || {}).mem_util || 0),
                online: !!v.online,
              });
            });
            list.sort(function (a, b) { return (b.cpu + b.mem) - (a.cpu + a.mem); });
            self.topHosts = list.slice(0, 10);
          });
      },
      _initCharts() {
        var self = this;
        try {
          self.chartInstances.group = echarts.init(self.$refs.groupChart);
          self.chartInstances.os = echarts.init(self.$refs.osChart);
          self.chartInstances.manage = echarts.init(self.$refs.manageChart);
          self.chartInstances.alarmTrend = echarts.init(self.$refs.alarmTrendChart);
          self._updateCharts();
        } catch (e) {
          console.error('echarts init error:', e);
        }
      },
      _updateCharts() {
        var self = this;
        if (!self.chartInstances.group) return;
        // 分组
        self.chartInstances.group.setOption({
          tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
          legend: { bottom: 0, type: 'scroll', textStyle: { fontSize: 11 } },
          series: [{
            type: 'pie', radius: ['35%', '65%'], center: ['50%', '42%'],
            data: self._groups.map(function (g) { return { name: g.name, value: g.count }; }),
            label: { show: false },
          }],
        });
        // 系统
        self.chartInstances.os.setOption({
          tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
          legend: { bottom: 0, textStyle: { fontSize: 11 } },
          series: [{
            type: 'pie', radius: ['35%', '65%'], center: ['50%', '42%'],
            data: ['Linux', 'Windows', 'Other'].map(function (k) { return { name: k, value: self._osStat[k] || 0 }; }),
            label: { show: false },
          }],
        });
        // 纳管
        self.chartInstances.manage.setOption({
          tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
          legend: { bottom: 0, textStyle: { fontSize: 11 } },
          series: [{
            type: 'pie', radius: ['35%', '65%'], center: ['50%', '42%'],
            data: [{ name: 'SSH', value: self._manageStat.ssh }, { name: 'Agent', value: self._manageStat.agent }],
            label: { show: false },
          }],
        });
        // 告警趋势（24h）
        var buckets = {};
        for (var i = 23; i >= 0; i--) {
          var d = new Date(Date.now() - i * 3600 * 1000);
          buckets[d.getHours()] = 0;
        }
        self.alarms.forEach(function (a) {
          if (a.lastchange) {
            var h = new Date(parseInt(a.lastchange) * 1000).getHours();
            if (buckets[h] !== undefined) buckets[h]++;
          }
        });
        self.chartInstances.alarmTrend.setOption({
          tooltip: { trigger: 'axis' },
          xAxis: { type: 'category', data: Object.keys(buckets), axisLabel: { fontSize: 10 } },
          yAxis: { type: 'value', minInterval: 1 },
          series: [{ type: 'bar', data: Object.values(buckets), itemStyle: { color: '#faad14' }, barMaxWidth: 18 }],
        });
      },
      fmtPct(v) {
        if (v === null || v === undefined || isNaN(v)) return '-';
        return (v || 0).toFixed(2) + '%';
      },
      onlineText(h) {
        return h.online === null ? '未知' : (h.online ? '在线' : '离线');
      },
      onlineCls(h) {
        return h.online === null ? 'mid' : (h.online ? 'on' : 'off');
      },
      priorityText(p) {
        var map = { 0: '未分类', 1: '信息', 2: '警告', 3: '严重', 4: '灾难', 5: '灾难' };
        return map[p] || '未知';
      },
      fmtTime(ts) {
        if (!ts) return '-';
        var d = new Date(parseInt(ts) * 1000);
        function p(n) { return (n < 10 ? '0' : '') + n; }
        return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
      },
      // ── 2026-08-17：统计卡点击下钻 ──────────────────────────
      // 2026-08-17：在线判断按监控类型取对应状态（Prometheus 主机 zabbix_agent_state 恒 false，不能只看它）
      _isOnline: function (h) {
        if (h.monitor_type === 'Prometheus') {
          return !!(h.prom_state && h.prom_state.state === '正常');
        }
        if (h.monitor_type === 'Zabbix') {
          return h.zabbix_agent_state === true;
        }
        return !!(h.zabbix_state && h.zabbix_state.state === '正常');
      },
      openCard: function (type) {
        if (type === 'total') this.showHosts('all');
        else if (type === 'online') this.showHosts('online');
        else if (type === 'offline') this.showHosts('offline');
        else if (type === 'alarm' || type === 'monitored') this.showAlarms();
      },
      showHosts: function (filter) {
        var self = this;
        self.hostFilter = filter || 'all';
        self.view = 'hosts';
        self.hostLoading = true;
        self.hostRows = [];
        fetchJson(API.hostList + '?page=1&per_page=200')
          .then(function (res) {
            var d = (res && res.data) || {};
            var list = d.data || [];
            // 用 host-list 秒开渲染。在线判断用 _isOnline（按监控类型：Zabbix→zabbix_agent_state，Prometheus→prom_state）
            self.hostRows = list.map(function (h) {
              return {
                ip: h.ip,
                name: h.show_name || h.name || h.ip,
                system: h.system_type || h.system_name || '-',
                manage: (h.control_type && h.control_type.state) || (h.agent_state && h.agent_state.state) || '-',
                cpu: null,
                mem: null,
                online: self._isOnline(h),
              };
            });
            self.hostLoading = false;
            // 2026-08-17：分批并发查 realtime（111 台一次性 item.get 慢且易超时），
            // 拆 2 批 ~56 台并发请求（Promise.all），总耗时 ≈ 单批。
            var ips = list.map(function (h) { return h.ip; }).filter(Boolean);
            if (!ips.length) return;
            var BATCH = 56;
            var batches = [];
            for (var i = 0; i < ips.length; i += BATCH) {
              var seg = ips.slice(i, i + BATCH);
              batches.push(fetchJson(API.realtime + '?ips=' + encodeURIComponent(seg.join(',')) + '&metrics=cpu_util,mem_util').catch(function () { return { data: {} }; }));
            }
            Promise.all(batches).then(function (results) {
              var rt = {};
              results.forEach(function (r) { if (r && r.data) Object.assign(rt, r.data); });
              self.hostRows = self.hostRows.map(function (h) {
                var v = rt[h.ip] || {};
                var cv = parseFloat((v.values || {}).cpu_util);
                var mv = parseFloat((v.values || {}).mem_util);
                if (!isNaN(cv)) h.cpu = cv;
                if (!isNaN(mv)) h.mem = mv;
                return h;
              });
            });
          })
          .catch(function () { self.hostLoading = false; });
      },
      showAlarms: function () {
        this.view = 'alarms';
      },
      backToDash: function () {
        this.view = 'dash';
      },
      goDetail(ip) {
        // 2026-08-17 v3：抽屉弹窗（不跳新窗口），iframe 内嵌生产平台 CMDB importdetail。
        // cmdb_base 来自后端 config：测试环境=正式平台(跨域需正式平台cookie)；正式部署配 HOST_MONITOR_CMDB_BASE=/o/cmdb（同域无跨域）
        var base = this._cmdbBase || 'https://192.168.99.24/o/cmdb';
        this.drawerHost = ip;
        this.drawerUrl = base + '/#/importdetail?model_code=VIRTUAL_SERVER&unique=' + encodeURIComponent(ip) + '&hideBackBtn=true';
      },
      closeDrawer() {
        this.drawerHost = null;
        this.drawerUrl = '';
      },
    },
    computed: {
      filteredHosts: function () {
        var f = this.hostFilter;
        if (f === 'all') return this.hostRows;
        var want = f === 'online';
        return this.hostRows.filter(function (h) { return h.online === want; });
      },
    },
  });

  window.__hostMonitorApp = app;
})();