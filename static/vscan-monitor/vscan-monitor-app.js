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
    webStats: '/t/esight/api/v1/cmdb/vscan/web/stats/',
    webSites: '/t/esight/api/v1/cmdb/vscan/web/sites/',
    webVulns: '/t/esight/api/v1/cmdb/vscan/web/vulns/',
    webDetail: '/t/esight/api/v1/cmdb/vscan/web/vulns/detail/',
    webCards: '/t/esight/api/v1/cmdb/vscan/web/cards/',
    webFull: '/t/esight/api/v1/cmdb/vscan/web/full/',
    webHigh: '/t/esight/api/v1/cmdb/vscan/web/high/',
    webSync: '/t/esight/api/v1/cmdb/vscan/web/sync/',
    webCompare: '/t/esight/api/v1/cmdb/vscan/web/compare/',
    vulnSync: '/t/esight/api/v1/cmdb/vscan/vuln/sync/',
    vulnsExport: '/t/esight/api/v1/cmdb/vscan/vulns/export/',
    webVulnsExport: '/t/esight/api/v1/cmdb/vscan/web/vulns/export/',
  };

  function fetchJson(url, opts) {
    var o = opts || {};
    o.credentials = 'include';
    o.headers = o.headers || {};
    o.headers['X-Requested-With'] = 'XMLHttpRequest';
    return fetch(url, o).then(function (r) { return r.json(); });
  }

  var SEV_TEXT = { '0': '信息', '1': '低', '2': '中', '3': '高', '4': '严重' };
  // 风险等级 → 配色（按风险语义：高=红/严重=深红、低=绿、中=橙、信息=灰）。
  // 2026-08-31：所有需要展示"风险等级颜色"的地方必须从这张表取色，禁止散落硬编码。
  // 与 vscan-index.html 的 .vs-pill.{info,low,mid,high,crit} 配色保持一致。
  var SEV_COLORS = {
    '信息': '#8c8c8c',
    '低':   '#52c41a',
    '中':   '#faad14',
    '高':   '#ff4d4f',
    '严重': '#cf1322',
  };
  var SEV_CLS = { '0': 'info', '1': 'low', '2': 'mid', '3': 'high', '4': 'crit' };
  // WEB 漏洞等级（scanlogsystem 与系统漏洞相反！）：0=高/1=中/2=低/3=信息
  var SEV_WEB_TEXT = { '0': '高', '1': '中', '2': '低', '3': '信息' };
  var SEV_WEB_CLS = { '0': 'high', '1': 'mid', '2': 'low', '3': 'info' };

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
        vulnTotalExact: 0,     // vScan 精确总数（iTotalRecords，池拉满后与池一致）
        vulnOffset: 0,
        vulnLoading: false,
        vulnExhausted: false,  // 池是否拉完（vScan 返回数据 < pageSize 或已 ≥ 精确总数）
        f: { ip: '', name: '', severity: '', asset_name: '', port: '' },
        // 资产视图
        assetList: [],
        aF: { ip: '' },
        // WEB 漏洞视图（落库 + 懒检测同步）在线查询样式
        webStats: { task_total: 0, tasks: [] },
        webCards: { task_total: 0, cards: [] },
        webCardsLoading: false,
        webCurrentTaskid: '',    // 当前选中的任务（默认第一条 = 最新报告）
        webTaskVulns: [],        // 当前任务去重漏洞列表
        webTaskVulnsLoading: false,
        webTaskVulnsErr: '',
        webSyncBuilding: false,  // 后台同步中
        webSyncMsg: '',          // 同步进度文案
        webSyncDoneTasks: 0,
        webSyncTotalTasks: 0,
        webCheckDone: false,     // 懒检测已完成
        webSyncErr: '',
        // 系统漏洞视图（落库 + 懒检测同步，镜像 WEB）
        vulnCheckDone: false,
        vulnSyncBuilding: false, // 后台同步中
        vulnSyncMsg: '',
        vulnSyncDoneTasks: 0,
        vulnSyncTotalTasks: 0,
        vulnSyncErr: '',
        // 报告对比
        showCompare: false,
        cmpA: '',                // 对比任务A（最新）
        cmpB: '',                // 对比任务B（上次）
        cmpResult: null,
        cmpLoading: false,
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
      // ⚠️ 2026-08-24 v15：资产视图搜索 = 前端过滤完整 assetList（原搜索无效）
      filteredAssets: function () {
        var q = (this.aF.ip || '').trim().toLowerCase();
        if (!q) return this.assetList;
        return this.assetList.filter(function (a) {
          return (a.ip || '').toLowerCase().indexOf(q) > -1 || (a.name || '').toLowerCase().indexOf(q) > -1;
        });
      },
    },
    mounted: function () {
      this.loadAll();
      var self = this;
      // ⚠️ 2026-08-22：移除 60s 自动刷新——vScan 数据是周报级，自动刷新无意义且每次打 vScan。
      // 需要最新数据点右上角"刷新"按钮（loadAll），或切走再切回。
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
      // 2026-08-21 v2：stats 变化只 updateCharts（不 dispose 重建，否则 chartsInited 反复重置导致不渲染）
      stats: {
        deep: false,
        handler: function () {
          if (this.view !== 'dash') return;
          var self = this;
          // 第一次：等 DOM 就绪后 init；后续：只 update
          this.$nextTick(function () {
            self._tryInitCharts();
            if (self.chartsInited) self._updateCharts();
          });
        }
      },
      view: function (v) {
        var self = this;
        if (v === 'dash') {
          // 切回大屏：DOM 重建了，需重新 init
          Object.keys(self.chartInstances).forEach(function (k) {
            if (self.chartInstances[k]) { try { self.chartInstances[k].dispose(); } catch (e) {} }
            delete self.chartInstances[k];
          });
          setTimeout(function () { self._tryInitCharts(); }, 200);
          setTimeout(function () { self._tryInitCharts(); }, 600);
        } else if (v === 'vulns') {
          if (self.dataPool.length === 0) self.loadVulnView();
        } else if (v === 'assets') {
          if (self.assetList.length === 0) self.loadVulnView();
        } else if (v === 'web') {
          self.loadWebView();
        }
      },
    },
    methods: {
      sevText: function (s) { return SEV_TEXT[String(s)] || s || '-'; },
      sevCls: function (s) { return SEV_CLS[String(s)] || ''; },
      // force=true 时带 ?refresh=1 强制回源（后端 1 天缓存的手动刷新入口）
      loadAll: function (force) {
        force = force === true;
        var self = this;
        this.loading = true;
        this.error = '';
        var statsUrl = force ? API.stats + '?refresh=1' : API.stats;
        var webStatsUrl = force ? API.webStats + '?refresh=1' : API.webStats;
        fetchJson(statsUrl).then(function (j) {
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
        // WEB 统计（任务维度，轻量）
        fetchJson(webStatsUrl).then(function (j) {
          if (j.code === 200) self.webStats = j.data || self.webStats;
        }).catch(function () {});
      },
      switchView: function (v) {
        this.view = v;
        if (v === 'vulns' && this.dataPool.length === 0) this.loadVulnView();
        if (v === 'assets' && this.assetList.length === 0) this.loadVulnView();
        if (v === 'web') this.loadWebView();
      },
      // ── WEB 漏洞视图（落库 + 懒检测同步：任务下拉 + 漏洞表）──
      sevWebText: function (s) { return SEV_WEB_TEXT[String(s)] || s || '-'; },
      sevWebCls: function (s) { return SEV_WEB_CLS[String(s)] || ''; },
      // 懒检测：DB 已是最新 → 直接查 DB；有新报告 → 后台同步 + 轮询
      loadWebView: function () {
        var self = this;
        if (this.webCardsLoading || this.webSyncBuilding) return;
        if (this.webCheckDone && this.webCards.cards.length > 0) {
          if (!this.webCurrentTaskid) this._pickFirstTask();
          return;
        }
        fetchJson(API.webSync + '?action=check').then(function (j) {
          if (j.code !== 200) { self.error = j.message || '同步检查失败'; return; }
          var d = j.data || {};
          if (d.fresh) {
            // 已是最新 → 查 DB 展示
            self.webCheckDone = true;
            self.loadWebCards();
          } else {
            // 有新报告 → 触发同步
            self.syncNow();
          }
        }).catch(function (e) {
          self.error = '同步检查请求失败: ' + e;
          self.loadWebCards(); // 降级：直接查 DB
        });
      },
      // 手动/自动触发同步
      syncNow: function () {
        var self = this;
        if (this.webSyncBuilding) return;
        this.webSyncBuilding = true;
        this.webSyncErr = '';
        fetchJson(API.webSync + '?action=trigger').then(function (j) {
          if (j.code !== 200) {
            self.webSyncBuilding = false;
            self.webSyncErr = j.message || '同步触发失败';
            self.loadWebCards(); // 降级
            return;
          }
          var d = j.data || {};
          if (d.fresh) {
            self.webSyncBuilding = false;
            self.webCheckDone = true;
            self.loadWebCards();
          } else {
            self._pollWebSync();
          }
        }).catch(function (e) {
          self.webSyncBuilding = false;
          self.webSyncErr = '同步请求失败: ' + e;
          self.loadWebCards();
        });
      },
      _pollWebSync: function () {
        var self = this;
        fetchJson(API.webSync + '?action=status').then(function (j) {
          if (j.code !== 200) { self.webSyncErr = j.message || '同步状态失败'; return; }
          var d = j.data || {};
          if (d.building) {
            self.webSyncMsg = d.msg || '同步中';
            self.webSyncDoneTasks = d.done_tasks || 0;
            self.webSyncTotalTasks = d.total_tasks || 0;
            setTimeout(function () { self._pollWebSync(); }, 2000);
          } else {
            self.webSyncBuilding = false;
            self.webCheckDone = true;
            self.loadWebCards();
          }
        }).catch(function (e) {
          self.webSyncBuilding = false;
          self.webSyncErr = '同步状态请求失败: ' + e;
          self.loadWebCards();
        });
      },
      // 查 DB 任务列表
      // ── 系统漏洞视图（落库 + 懒检测同步，镜像 WEB 漏洞）──
      // 懒检测：DB 有新鲜数据 → 直接读 DB（秒开）；否则触发后台同步 + 轮询
      loadVulnView: function (force) {
        force = force === true;
        var self = this;
        if (this.vulnSyncBuilding) return;
        var doLoad = function () {
          // 根据当前视图加载对应数据（DB 秒开）
          if (self.view === 'assets') {
            if (self.assetList.length === 0) self.loadAssets();
          } else {
            if (self.dataPool.length === 0) self.searchVulns();
          }
        };
        if (force) { self.vulnSyncNow(doLoad); return; }
        fetchJson(API.vulnSync + '?action=check').then(function (j) {
          if (j.code !== 200) { self.error = j.message || '同步检查失败'; doLoad(); return; }
          var d = j.data || {};
          if (d.fresh) {
            self.vulnCheckDone = true;
            doLoad();
          } else {
            self.vulnSyncNow(doLoad);
          }
        }).catch(function (e) {
          self.error = '同步检查请求失败: ' + e;
          doLoad();
        });
      },
      // 手动/自动触发同步
      vulnSyncNow: function (cb) {
        cb = cb || function () {};
        var self = this;
        if (this.vulnSyncBuilding) return;
        this.vulnSyncBuilding = true;
        this.vulnSyncErr = '';
        fetchJson(API.vulnSync + '?action=trigger').then(function (j) {
          if (j.code !== 200) {
            self.vulnSyncBuilding = false;
            self.vulnSyncErr = j.message || '同步触发失败';
            cb();
            return;
          }
          var d = j.data || {};
          if (d.fresh) {
            self.vulnSyncBuilding = false;
            self.vulnCheckDone = true;
            cb();
          } else {
            self._pollVulnSync(cb);
          }
        }).catch(function (e) {
          self.vulnSyncBuilding = false;
          self.vulnSyncErr = '同步请求失败: ' + e;
          cb();
        });
      },
      _pollVulnSync: function (cb) {
        cb = cb || function () {};
        var self = this;
        fetchJson(API.vulnSync + '?action=status').then(function (j) {
          if (j.code !== 200) { self.vulnSyncErr = j.message || '同步状态失败'; cb(); return; }
          var d = j.data || {};
          if (d.building) {
            self.vulnSyncMsg = d.msg || '同步中';
            self.vulnSyncDoneTasks = d.done_tasks || 0;
            self.vulnSyncTotalTasks = d.total_tasks || 0;
            if (d.vuln_total) self.vulnSyncMsg = (d.msg || '同步中') + '（' + d.vuln_total + ' 条）';
            setTimeout(function () { self._pollVulnSync(cb); }, 2000);
          } else {
            self.vulnSyncBuilding = false;
            self.vulnCheckDone = true;
            cb();
          }
        }).catch(function (e) {
          self.vulnSyncBuilding = false;
          self.vulnSyncErr = '同步状态请求失败: ' + e;
          cb();
        });
      },
      loadWebCards: function () {
        var self = this;
        if (this.webCardsLoading) return;
        this.webCardsLoading = true;
        this.error = '';
        fetchJson(API.webCards).then(function (j) {
          self.webCardsLoading = false;
          if (j.code === 200) {
            self.webCards = j.data || self.webCards;
            self._pickFirstTask();
          } else {
            self.error = j.message || 'WEB 任务列表加载失败';
          }
        }).catch(function (e) {
          self.webCardsLoading = false;
          self.error = 'WEB 任务列表请求失败: ' + e;
        });
      },
      _pickFirstTask: function () {
        // 自动选中第一条有数据的任务（最新报告）
        var cards = this.webCards.cards || [];
        var pick = null;
        for (var i = 0; i < cards.length; i++) {
          if (cards[i].vuln_total > 0 || cards[i].site_total > 0) { pick = cards[i]; break; }
        }
        if (pick && String(pick.taskid) !== String(this.webCurrentTaskid)) {
          this.selectWebTask(pick.taskid);
        }
      },
      // 选择任务 → 查 DB 漏洞（秒开）
      selectWebTask: function (taskid) {
        var self = this;
        this.webCurrentTaskid = String(taskid);
        this.webTaskVulns = [];
        this.webTaskVulnsErr = '';
        this.webTaskVulnsLoading = true;
        this.error = '';
        var q = '?taskid=' + taskid;
        fetchJson(API.webVulns + q).then(function (j) {
          self.webTaskVulnsLoading = false;
          if (j.code === 200) {
            self.webTaskVulns = j.data.data || [];
          } else {
            self.webTaskVulnsErr = j.message || '漏洞列表加载失败';
          }
        }).catch(function (e) {
          self.webTaskVulnsLoading = false;
          self.webTaskVulnsErr = '漏洞列表请求失败: ' + e;
        });
      },
      // ── 报告对比（整改对比）──
      openCompare: function () {
        var cards = this.webCards.cards || [];
        // 默认选前两个【有数据】的任务（跳过无数据的空报告）
        var withData = [];
        for (var i = 0; i < cards.length; i++) {
          if (cards[i].vuln_total > 0) withData.push(cards[i]);
          if (withData.length >= 2) break;
        }
        if (withData.length >= 2) {
          this.cmpA = String(withData[0].taskid);
          this.cmpB = String(withData[1].taskid);
        }
        this.showCompare = true;
        this.cmpResult = null;
      },
      closeCompare: function () { this.showCompare = false; this.cmpResult = null; },
      doCompare: function () {
        var self = this;
        if (!this.cmpA || !this.cmpB || this.cmpA === this.cmpB) return;
        this.cmpLoading = true;
        this.cmpResult = null;
        var q = '?a=' + this.cmpA + '&b=' + this.cmpB;
        fetchJson(API.webCompare + q).then(function (j) {
          self.cmpLoading = false;
          if (j.code === 200) self.cmpResult = j.data;
          else self.cmpResult = { err: j.message || '对比失败' };
        }).catch(function (e) {
          self.cmpLoading = false;
          self.cmpResult = { err: '请求失败: ' + e };
        });
      },
      currentWebTaskName: function () {
        var cards = this.webCards.cards || [];
        for (var i = 0; i < cards.length; i++) {
          if (String(cards[i].taskid) === String(this.webCurrentTaskid)) return cards[i].name;
        }
        return '';
      },
      taskNameOf: function (taskid) {
        var cards = this.webCards.cards || [];
        for (var i = 0; i < cards.length; i++) {
          if (String(cards[i].taskid) === String(taskid)) return cards[i].name;
        }
        return '任务 ' + taskid;
      },
      openWebVuln: function (v) {
        var self = this;
        this.drawer = { name: v.name || '', web: true };
        this.detail = {};
        this.detailLoading = true;
        var q = '?pluginid=' + encodeURIComponent(v.pluginid);
        fetchJson(API.webDetail + q).then(function (j) {
          self.detailLoading = false;
          if (j.code === 200 && j.data) {
            self.detail = j.data || {};
            // scanplugins/detail 插件定义不含实例 URL → 用列表行 url 兜底
            if (!self.detail.url) self.detail.url = v.url;
            if (!self.detail.severity) self.detail.severity = { id: String(v.severity.id), text: v.severity.text, cls: v.severity.cls };
          } else {
            // 详情失败 → 用列表自带字段兜底
            self.detail = {
              name: v.name, comment: v.comment, param: v.param, testcase: v.testcase,
              url: v.url, severity: v.severity, error: null,
            };
          }
        }).catch(function (e) {
          self.detailLoading = false;
          self.detail = { name: v.name, comment: v.comment, param: v.param, testcase: v.testcase,
                          url: v.url, severity: v.severity, error: '请求失败: ' + e };
        });
      },
      // ── 漏洞列表（前端过滤 + 分页池）──
      // 2026-08-26：数据来自本地 DB（秒开），不再带 ?refresh=1；
      // 强制重新拉上游请用 loadVulnView(true)（同步数据按钮）
      searchVulns: function () {
        // 重置：清池，按当前 f 重新拉
        this.dataPool = [];
        this.vulnOffset = 0;
        this.vulnExhausted = false;
        this.vulnTotalExact = 0;
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
        var list = this.dataPool.filter(function (v) { return matchFilter(v, f2); });
        // 2026-08-31：风险等级从高到低排序（sev: '4'=严重 '3'=高 '2'=中 '1'=低 '0'=信息）
        // 同级按名称稳定排，保证「全部风险等级」视图下高危项置顶、列表有序不抖动。
        list.sort(function (a, b) {
          var sa = Number(a.sev), sb = Number(b.sev);
          if (sb !== sa) return sb - sa;            // 高 → 低
          return (a.name || '').localeCompare(b.name || '', 'zh');
        });
        this.filteredVulns = list;
      },
      fetchVulnsIntoPool: function (force) {
        var self = this;
        if (this.vulnLoading || this.vulnExhausted) return;
        this.vulnLoading = true;
        // DB 读取（秒开），无需 ?refresh=1
        var q = '?limit=500&offset=' + this.vulnOffset;
        fetchJson(API.vulns + q).then(function (j) {
          self.vulnLoading = false;
          if (j.code !== 200) {
            self.error = j.message || '漏洞列表加载失败';
            return;
          }
          var rows = (j.data && j.data.data) || [];
          var totalExact = (j.data && j.data.total) || 0;
          // 标准化 vScan 行到统一字段（severity.id → sev）
          for (var i = 0; i < rows.length; i++) {
            var v = rows[i];
            v.sev = (v.severity && v.severity.id !== undefined) ? v.severity.id : v.severity;
          }
          self.dataPool = self.dataPool.concat(rows);
          self.vulnTotalPool = self.dataPool.length;
          self.vulnTotalExact = totalExact || self.dataPool.length;
          self.vulnOffset += 500;
          // 拉满判定：vScan 返回不足一页 或 池已达精确总数
          if (rows.length < 500 || self.dataPool.length >= self.vulnTotalExact) {
            self.vulnExhausted = true;
          }
          self.applyFilter();
          // 2026-08-21：还有剩余 → 自动继续拉（进入列表即拉满全量，筛选在全量上做）
          if (!self.vulnExhausted) {
            self.fetchVulnsIntoPool(force);
          }
        }).catch(function (e) {
          self.vulnLoading = false;
          self.error = '请求失败: ' + e;
        });
      },
      loadMoreVulns: function () {
        // 池里过滤后条数 < 池总量 → 池可能不够，再拉更多
        this.fetchVulnsIntoPool();
      },
      // 2026-08-28：导出系统漏洞（CSV，所见即所导：把当前筛选 f 原样传给后端）
      exportVulns: function () {
        var f = this.f;
        var q = 'ip=' + encodeURIComponent(f.ip || '') +
                '&name=' + encodeURIComponent(f.name || '') +
                '&severity=' + encodeURIComponent(f.severity || '') +
                '&asset_name=' + encodeURIComponent(f.asset_name || '') +
                '&port=' + encodeURIComponent(f.port || '');
        window.open(API.vulnsExport + '?' + q, '_blank');
      },
      // 2026-08-28：导出 WEB 漏洞（当前选中任务）
      exportWebVulns: function () {
        if (!this.webCurrentTaskid) return;
        window.open(API.webVulnsExport + '?taskid=' + encodeURIComponent(this.webCurrentTaskid), '_blank');
      },
      // ── 资产视图 ──
      // ⚠️ 2026-08-24 v15：拉【全量】漏洞分页聚合资产（原来只拉第一页 500 条 → 资产不全、
      // 且后端忽略 ip 参数导致搜索失效）。搜索改前端过滤 filteredAssets。
      // 2026-08-26：数据来自本地 DB（秒开），无需 ?refresh=1。
      loadAssets: function () {
        var self = this;
        if (this.loading) return;
        this.loading = true;
        this.error = '';
        var all = [];
        var start = 0;
        var total = null;
        (function fetchPage() {
          var q = '?limit=500&offset=' + start;
          fetchJson(API.vulns + q).then(function (j) {
            if (j.code !== 200) { self.loading = false; self.error = j.message || '资产加载失败'; return; }
            var d = j.data || {};
            if (total === null) total = d.total || 0;
            all = all.concat(d.data || []);
            if ((d.data || []).length >= 500 && all.length < total) {
              start += 500;
              fetchPage();
              return;
            }
            self.loading = false;
            var map = {};
            all.forEach(function (v) {
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
        })();
      },
      filterByAsset: function (a) {
        // 资产"查看漏洞"：切到 vulns 视图 + 设筛选条件 + 重置池
        this.f.ip = a.ip || '';
        this.f.asset_name = a.name || '';
        this.f.name = '';
        this.f.severity = '';
        this.f.port = '';
        this.view = 'vulns';
        // 确保数据已就绪（DB 秒开；若未同步则触发同步）
        this.loadVulnView();
      },
      // 2026-08-24 v15：资产搜索 = 前端过滤（computed filteredAssets 自动响应 aF.ip）
      onAssetSearch: function () {
        // 资产"查询"按钮 = 重新从 DB 加载全量聚合（秒开）
        this.loadAssets();
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
          // 按【风险等级名称】取色（不再依赖 sev_dist 数组顺序）：
          // 后端 sorted() 在 3 桶（低/中/高） vs 5 桶（信息/低/中/高/严重）下顺序不同，
          // 改用 itemStyle.color 逐项绑定，免疫错位。
          var pieData = (this.stats.sev_dist || []).map(function (d) {
            return {
              name: d.severity,
              value: d.cnt,
              itemStyle: { color: SEV_COLORS[d.severity] || '#8c8c8c' },
            };
          });
          sev.setOption({
            tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
            legend: { bottom: 0, textStyle: { fontSize: 12 } },
            series: [{
              type: 'pie', radius: ['38%', '62%'], center: ['50%', '44%'],
              label: { show: false },
              data: pieData,
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
