// eSight 漏洞扫描大屏 - vScan（华为 VSCAN1506）实时透传 v2
// 数据源：eSight 后端 /vscan/stats/ /vscan/tasks/ /vscan/vulns/ /vscan/vulns/detail/
//
// 2026-08-21 v2 关键改动：
//   1. 筛选：vScan queryplugin 后端不接受任意过滤参数（实测 iTotalRecords 始终=773）
//      → 改为前端过滤：拿全量 500 条/批进入 dataPool，按 f 过滤显示
//   2. 图表：stats 二次更新时 chartInstances 绑在已卸载的 DOM 上 → watch 直接 dispose 重建
//   3. 跳转：filterByAsset 切到 vulns 视图后筛选池已加载 → 切视图即可立即看到筛选结果
(function () {
  'use strict';
  var API = {
    stats: '/t/esight/api/v1/cmdb/vscan/stats/',
    tasks: '/t/esight/api/v1/cmdb/vscan/tasks/',
    vulns: '/t/esight/api/v1/cmdb/vscan/vulns/',
    detail: '/t/esight/api/v1/cmdb/vscan/vulns/detail/',
  };

  function fetchJson(url, opts) {
    var o = opts || {};
    o.credentials = 'include';
    o.headers = o.headers || {};
    o.headers['X-Requested-With'] = 'XMLHttpRequest';
    return fetch(url, o).then(function (r) { return r.json(); });
  }

  var SEV_TEXT = { '0': '信息', '1': '低', '2': '中', '3': '高', '4': '严重' };
  var SEV_CLS = { '0': 'info', '1': 'low', '2': 'mid', '3': 'high', '4': 'crit' };

  function matchFilter(v, f) {
    if (f.ip && (v.ip || '').indexOf(f.ip) === -1) return false;
    if (f.name && (v.name || '').indexOf(f.name) === -1) return false;
    if (f.severity !== '' && f.severity !== undefined && String(v.sev) !== String(f.severity)) return false;
    if (f.asset_name && (v.asset_name || '').indexOf(f.asset_name) === -1) return false;
    if (f.port && String(v.port) !== String(f.port)) return false;
    return true;
  }

  var app = new Vue({
    el: '#app',
    data: function () {
      return {
        loading: true,
        error: '',
        view: 'dash',
        stats: { vuln_total: 0, high_cnt: 0, task_total: 0, task_running: 0, task_finished: 0, sev_dist: [], top_assets: [], recent: [] },
        chartInstances: {},
        // 漏洞列表（前端过滤 + 池）
        dataPool: [],          // 全量数据池（按需分页拉取累积）
        filteredVulns: [],     // 过滤后展示
        vulnTotalPool: 0,      // 池总量（不是 vScan 总数）
        vulnOffset: 0,
        vulnLoading: false,
        vulnExhausted: false,  // 池是否拉完（vScan 返回数据 < pageSize）
        f: { ip: '', name: '', severity: '', asset_name: '', port: '' },
        // 资产视图
        assetList: [],
        aF: { ip: '' },
        // 详情抽屉
        drawer: null,
        detail: {},
        detailLoading: false,
        _timer: null,
      };
    },
    computed: {
      vulns: function () { return this.filteredVulns; },
      vulnTotal: function () { return this.filteredVulns.length; },
    },
    mounted: function () {
      this.loadAll();
      var self = this;
      this._timer = setInterval(function () { if (self.view === 'dash') self.loadAll(); }, 60000);
      window.addEventListener('beforeunload', function () { clearInterval(self._timer); });
      window.addEventListener('resize', function () {
        Object.keys(self.chartInstances).forEach(function (k) {
          if (self.chartInstances[k]) self.chartInstances[k].resize();
        });
      });
      window.addEventListener('keydown', function (e) {
        if (e.key === 'Escape' && self.drawer) self.closeDrawer();
      });
      window.addEventListener('click', function (e) {
        if (!self.drawer) return;
        var d = document.querySelector('.vs-drawer');
        if (d && !d.contains(e.target)) self.closeDrawer();
      });
      setTimeout(function () { self._tryInitCharts(); }, 200);
      setTimeout(function () { self._tryInitCharts(); }, 800);
    },
    watch: {
      // 2026-08-21 v2：stats 任何字段变化都触发图表重建（dispose 旧实例避免 DOM ref 失效）
      stats: {
        deep: false,
        handler: function () {
          if (this.view !== 'dash') return;
          Object.keys(this.chartInstances).forEach(function (k) {
            if (this.chartInstances[k]) { try { this.chartInstances[k].dispose(); } catch (e) {} }
            delete this.chartInstances[k];
          }.bind(this));
          var self = this;
          this.$nextTick(function () { self._tryInitCharts(); });
        }
      },
      view: function (v) {
        var self = this;
        if (v === 'dash') {
          // 重新挂载图表
          Object.keys(self.chartInstances).forEach(function (k) {
            if (self.chartInstances[k]) { try { self.chartInstances[k].dispose(); } catch (e) {} }
            delete self.chartInstances[k];
          });
          setTimeout(function () { self._tryInitCharts(); }, 200);
          setTimeout(function () { self._tryInitCharts(); }, 600);
        } else if (v === 'vulns') {
          // 切到漏洞列表：若池为空则加载
          if (self.dataPool.length === 0) self.searchVulns();
        } else if (v === 'assets') {
          if (self.assetList.length === 0) self.loadAssets();
        }
      },
    },
    methods: {
      sevText: function (s) { return SEV_TEXT[String(s)] || s || '-'; },
      sevCls: function (s) { return SEV_CLS[String(s)] || ''; },
      loadAll: function () {
        var self = this;
        this.loading = true;
        this.error = '';
        fetchJson(API.stats).then(function (j) {
          self.loading = false;
          if (j.code === 200) {
            self.stats = j.data || self.stats;
          } else {
            self.error = j.message || '数据加载失败';
          }
        }).catch(function (e) {
          self.loading = false;
          self.error = '请求失败: ' + e;
        });
      },
      switchView: function (v) {
        this.view = v;
        if (v === 'vulns' && this.dataPool.length === 0) this.searchVulns();
        if (v === 'assets' && this.assetList.length === 0) this.loadAssets();
      },
      // ── 漏洞列表（前端过滤 + 分页池）──
      searchVulns: function () {
        // 重置：清池，按当前 f 重新拉
        this.dataPool = [];
        this.vulnOffset = 0;
        this.vulnExhausted = false;
        this.fetchVulnsIntoPool();
        this.applyFilter();
      },
      applyFilter: function () {
        var self = this;
        var f = this.f;
        // 标准化 severity 字符串
        var f2 = { ip: (f.ip || '').trim(), name: (f.name || '').trim(), asset_name: (f.asset_name || '').trim(), port: (f.port || '').trim() };
        f2.severity = f.severity === '' || f.severity === undefined ? '' : String(f.severity);
        this._filter = f2;
        // 在 dataPool 上过滤
        this.filteredVulns = this.dataPool.filter(function (v) { return matchFilter(v, f2); });
      },
      fetchVulnsIntoPool: function () {
        var self = this;
        if (this.vulnLoading || this.vulnExhausted) return;
        this.vulnLoading = true;
        var q = '?limit=500&offset=' + this.vulnOffset;
        fetchJson(API.vulns + q).then(function (j) {
          self.vulnLoading = false;
          if (j.code !== 200) {
            self.error = j.message || '漏洞列表加载失败';
            return;
          }
          var rows = (j.data && j.data.data) || [];
          // 标准化 vScan 行到统一字段（severity.id → sev）
          for (var i = 0; i < rows.length; i++) {
            var v = rows[i];
            v.sev = (v.severity && v.severity.id !== undefined) ? v.severity.id : v.severity;
          }
          self.dataPool = self.dataPool.concat(rows);
          self.vulnTotalPool = self.dataPool.length;
          if (rows.length < 500) self.vulnExhausted = true;
          self.vulnOffset += 500;
          self.applyFilter();
        }).catch(function (e) {
          self.vulnLoading = false;
          self.error = '请求失败: ' + e;
        });
      },
      loadMoreVulns: function () {
        // 池里过滤后条数 < 池总量 → 池可能不够，再拉更多
        this.fetchVulnsIntoPool();
      },
      // ── 资产视图 ──
      loadAssets: function () {
        var self = this;
        this.loading = true;
        var q = '?limit=500';
        if (this.aF.ip) q += '&ip=' + encodeURIComponent(this.aF.ip);
        fetchJson(API.vulns + q).then(function (j) {
          self.loading = false;
          if (j.code !== 200) { self.error = j.message || '资产加载失败'; return; }
          var map = {};
          (j.data.data || []).forEach(function (v) {
            var sid = (v.severity && v.severity.id !== undefined) ? v.severity.id : v.severity;
            var key = v.ip || v.asset_name || '未知';
            var a = map[key] || { name: v.asset_name || key, ip: v.ip || '', os: v.os || '', cnt: 0, high: 0 };
            a.cnt += 1;
            if (sid === '3' || sid === 3 || sid === '4' || sid === 4) a.high += 1;
            map[key] = a;
          });
          self.assetList = Object.keys(map).map(function (k) { return map[k]; })
            .sort(function (x, y) { return y.high - x.high || y.cnt - x.cnt; });
        }).catch(function (e) {
          self.loading = false;
          self.error = '请求失败: ' + e;
        });
      },
      filterByAsset: function (a) {
        // 资产"查看漏洞"：切到 vulns 视图 + 设筛选条件 + 重置池
        this.f.ip = a.ip || '';
        this.f.asset_name = a.name || '';
        this.f.name = '';
        this.f.severity = '';
        this.f.port = '';
        this.view = 'vulns';
        // view watch 会自动 searchVulns（若池为空），这里显式触发确保立即重新拉
        this.searchVulns();
      },
      // ── 详情 ──
      openVuln: function (v) {
        if (!v.rid) return;
        var self = this;
        this.drawer = v;
        this.detail = {};
        this.detailLoading = true;
        fetchJson(API.detail + '?pluginid=' + encodeURIComponent(v.rid)).then(function (j) {
          self.detailLoading = false;
          if (j.code === 200) {
            self.detail = j.data;
          } else {
            self.detail = { name: v.name, description: j.message || '详情加载失败', severity: { text: '', cls: '' } };
          }
        }).catch(function () {
          self.detailLoading = false;
          self.detail = { name: v.name, description: '请求失败', severity: { text: '', cls: '' } };
        });
      },
      closeDrawer: function () { this.drawer = null; this.detail = {}; },
      // ── 图表 ──
      _tryInitCharts: function () {
        if (this.view !== 'dash') return;
        if (!this.$refs.sevChart || !this.$refs.assetChart) return;
        if (typeof echarts === 'undefined') return;
        // 已存在则 dispose 重建
        Object.keys(this.chartInstances).forEach(function (k) {
          if (this.chartInstances[k]) { try { this.chartInstances[k].dispose(); } catch (e) {} }
          delete this.chartInstances[k];
        }.bind(this));
        try {
          this.chartInstances.sev = echarts.init(this.$refs.sevChart);
          this.chartInstances.asset = echarts.init(this.$refs.assetChart);
          this._updateCharts();
        } catch (e) {}
      },
      _updateCharts: function () {
        var sev = this.chartInstances.sev;
        var asset = this.chartInstances.asset;
        if (sev) {
          sev.setOption({
            color: ['#8c8c8c', '#52c41a', '#faad14', '#ff4d4f', '#cf1322'],
            tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
            legend: { bottom: 0, textStyle: { fontSize: 12 } },
            series: [{
              type: 'pie', radius: ['38%', '62%'], center: ['50%', '44%'],
              label: { show: false },
              data: (this.stats.sev_dist || []).map(function (d) { return { name: d.severity, value: d.cnt }; }),
            }],
          });
        }
        if (asset) {
          var tops = (this.stats.top_assets || []).slice(0, 10);
          asset.setOption({
            color: ['#ff4d4f'],
            tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
            grid: { left: 100, right: 20, top: 20, bottom: 30 },
            xAxis: { type: 'value', splitLine: { lineStyle: { type: 'dashed' } } },
            yAxis: {
              type: 'category',
              data: tops.map(function (a) { return a.ip || a.name; }).reverse(),
              axisLabel: { fontSize: 11 },
            },
            series: [{
              type: 'bar', barWidth: 14,
              itemStyle: { borderRadius: [0, 7, 7, 0] },
              label: { show: true, position: 'right' },
              data: tops.map(function (a) { return a.high; }).reverse(),
            }],
          });
        }
      },
    },
  });
})();
