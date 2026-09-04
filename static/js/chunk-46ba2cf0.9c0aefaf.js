(window.webpackJsonp=window.webpackJsonp||[]).push([["chunk-46ba2cf0"],{"0d49":function(e,t,a){var i={"./EditTitleForm.vue":"91eb","./ManagementCoverage.vue":"2ec9","./Monitoring.vue":"baa5","./Prom.vue":"224d","./ResourceFive.vue":"c4ef","./ResourceFour.vue":"bdca","./ResourceOne.vue":"a443","./ResourceSix.vue":"5e70","./ResourceThree.vue":"dd97","./ResourceTwo.vue":"5787","./WorkbenchFour.vue":"6201","./WorkbenchOne.vue":"6db3","./WorkbenchTwo.vue":"4a56","./SecurityOverviewCard.vue":"soc1"};function n(e){var t=o(e);return a(t)}function o(e){if(!a.o(i,e)){var t=new Error("Cannot find module '"+e+"'");throw t.code="MODULE_NOT_FOUND",t}return i[e]}n.keys=function(){return Object.keys(i)},n.resolve=o,e.exports=n,n.id="0d49"},2909:function(e,t,a){"use strict";a.d(t,"a",(function(){return o}));var i=a("6b75");a("a4d3"),a("e01a"),a("d28b"),a("a630"),a("d3b7"),a("3ca3"),a("ddb0");var n=a("06c5");function o(e){return function(e){if(Array.isArray(e))return Object(i.a)(e)}(e)||function(e){if("undefined"!=typeof Symbol&&null!=e[Symbol.iterator]||null!=e["@@iterator"])return Array.from(e)}(e)||Object(n.a)(e)||function(){throw new TypeError("Invalid attempt to spread non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.")}()}},"77b8":function(e,t,a){"use strict";a.r(t);var i=a("2909"),n=(a("a4d3"),a("e01a"),a("99af"),a("4de4"),a("b0c0"),a("d3b7"),a("5530")),o=(a("d81d"),a("ac1f"),a("5319"),a("159b"),a("7be8")),r=a("ca00"),s=a("3191"),c=a("b76a"),l=a.n(c),u=a("2ef0"),d={components:Object(n.a)({GridLayout:o.GridLayout,GridItem:o.GridItem,draggable:l.a},Object(r.a)(a("0d49"))),data:function(){return{url:window.API_ROOT.replace("/workbench",""),layout:[],draggable:!1,resizable:!1,loading:!1,activeTab:void 0,tabList:[],showArrow:!1,tabLoading:!1,homePageTabList:[],homePageTabLoading:!1}},methods:{getOverview:function(){var e=this;this.homePageTabLoading=!0,Object(s.o)().then((function(t){e.homePageTabList=t.data})).finally((function(){var t;(e.homePageTabLoading=!1,e.loading=!1,e.activeTab)||(e.activeTab=null===(t=e.homePageTabList[0])||void 0===t?void 0:t.id);e.getOverviewInfo(e.activeTab)}))},getOverviewInfo:function(e){var t=this;e&&(this.loading=!0,Object(s.o)({id:e}).then((function(e){t.layout=e.data.card_list.map((function(e){return Object(n.a)({},e.attribute)})).filter((function(e){return["resource_home_page_one","resource_home_page_two","resource_home_page_three","resource_home_page_four","resource_home_page_five","resource_home_page_six"].indexOf(e.unique)<0})).concat([{unique:"sec_waf",name:"WAF 攻击日志",x:0,y:0,w:9,h:8,i:"sec_waf",minW:5,minH:8,static:!1},{unique:"sec_fw",name:"防火墙日志",x:9,y:0,w:9,h:8,i:"sec_fw",minW:5,minH:8,static:!1},{unique:"sec_vuln",name:"漏洞扫描",x:0,y:8,w:9,h:9,i:"sec_vuln",minW:5,minH:9,static:!1},{unique:"sec_alert",name:"安全告警",x:9,y:8,w:9,h:9,i:"sec_alert",minW:5,minH:9,static:!1},{unique:"sec_host",name:"主机监控",x:0,y:17,w:18,h:9,i:"sec_host",minW:5,minH:9,static:!1}])})).finally((function(){t.loading=!1})))},getTemplateConfig:function(){var e=this;this.tabLoading=!0,Object(s.q)().then((function(t){e.tabList=t.data,e.tabList.forEach((function(t){t.children.forEach((function(t){e.$set(t,"bindLoading",!1)}))}))})).finally((function(){e.checkArrows(),e.tabLoading=!1}))},handleChangeBind:function(e,t){var a=this,i={data_type:"enable",panel_inst:e.id};e.bindLoading=!0,Object(s.t)(i).then((function(t){a.activeTab==e.id&&(a.activeTab=void 0),a.getTemplateConfig(),a.getOverview()})).finally((function(){e.bindLoading=!1}))},linkInfo:function(e,t){var a=e.id,i=e.name;this.$router.push({name:"homeSetting",query:{id:a,bind:t,name:i}})},dragHomePageTab:function(){var e=this.homePageTabList.map((function(e){return e.id}));Object(s.s)({data_type:"index",panel_inst_list:e})},resizeEvent:function(e,t,a,i,n){Object(r.b)()},scrollLeft:function(){this.$refs.tabRollBox.scrollTo({left:this.$refs.tabRollBox.scrollLeft-350,behavior:"smooth"}),this.checkArrows()},scrollRight:function(){this.$refs.tabRollBox.scrollTo({left:this.$refs.tabRollBox.scrollLeft+350,behavior:"smooth"}),this.checkArrows()},checkArrows:function(){var e=this.$refs.tabRollBox;this.showArrow=e.scrollWidth>e.clientWidth},handleResize:Object(u.debounce)((function(){this.checkArrows()}),300),destroyResize:function(){window.removeEventListener("resize",this.handleResize)},windowResize:function(){window.addEventListener("resize",this.handleResize),this.$on("hook:beforeDestroy",this.destroyResize)}},created:function(){this.language=this.$store.state.language.languageAuth.home||{}},mounted:function(){this.loading=!0,"1"==this.$route.query.bind&&(this.activeTab=this.$route.query.id||void 0),this.windowResize(),this.getTemplateConfig(),this.getOverview()}},g=(a("a00f"),a("2877")),h=Object(g.a)(d,(function(){var e=this,t=e._self._c;return t("div",{staticClass:"content"},[t("div",{staticClass:"content_header"},[t("div",{staticClass:"tab_box"},[t("div",{staticClass:"arrow_box",style:{display:e.showArrow?"block":"none"},on:{click:e.scrollLeft}},[t("a-icon",{attrs:{type:"left"}})],1),t("div",{ref:"tabRollBox",staticClass:"content_header_tab"},[t("a-spin",{staticClass:"tab_spin",attrs:{spinning:e.homePageTabLoading}},[t("draggable",{staticStyle:{display:"flex"},attrs:{animation:200,handle:".drag_icon"},on:{change:e.dragHomePageTab},model:{value:e.homePageTabList,callback:function(t){e.homePageTabList=t},expression:"homePageTabList"}},e._l(e.homePageTabList,(function(a){return t("div",{key:a.id,staticClass:"content_header_tab_item",class:{content_header_tab_item_active:a.id==e.activeTab},on:{click:function(){e.activeTab=a.id,e.getOverviewInfo(a.id)}}},[t("span",[t("div",{staticClass:"drag_icon"},[t("a-tooltip",{attrs:{title:e.language.drag_title1}},[t("a-icon",{attrs:{type:"drag"}})],1)],1),t("span",[e._v(e._s(a.name))]),a.can_update?t("div",{staticClass:"edit_icon"},[t("a-tooltip",{attrs:{title:e.language.drag_title2}},[t("a-icon",{attrs:{type:"edit"},nativeOn:{click:function(t){return t.stopPropagation(),e.linkInfo(a,"1")}}})],1)],1):e._e()])])})),0),t("a-popover",{attrs:{trigger:"click",placement:"bottomRight",overlayClassName:"custom_popover"}},[t("div",{staticClass:"panel_content",attrs:{slot:"content"},slot:"content"},[t("a-spin",{staticClass:"custom_spin",attrs:{spinning:e.tabLoading}},[t("div",{staticClass:"panel_content_title"},[t("strong",[e._v(" "+e._s(e.language.popover_title))]),t("div",{staticStyle:{padding:"5px 0"}},[e.$store.state.btnAuth.btnAuth?t("a-button",{staticStyle:{"margin-left":"10px"},attrs:{size:"small",type:"link"},on:{click:function(){return e.$router.push({name:"homeSetting"})}}},[t("a-icon",{attrs:{type:"plus-circle"}}),t("span",[e._v(e._s(e.language.popover_add))])],1):e._e()],1)]),t("div",{staticClass:"setting_panel"},[e._l(e.tabList,(function(a){return[a.children&&a.children.length?t("div",{staticClass:"group"},[t("div",{staticClass:"group_title"},[t("span",{staticClass:"group_title_name"},[e._v(e._s(a.group_name))]),t("span",{staticClass:"group_title_desc"},[e._v(e._s(a.description))])]),e._l(a.children,(function(a){return t("div",{staticClass:"setting_panel_item"},[t("div",{staticClass:"setting_panel_item_left"},[t("div",{staticClass:"title"},[t("span",{staticClass:"name"},[e._v(e._s(a.name))]),t("span",{staticClass:"tag"},[e._v(e._s(a.built_in?e.language.popover_build_in:a.public?e.language.popover_public:e.language.popover_private))]),a.can_update?t("a-tooltip",{attrs:{title:e.language.popover_edit}},[t("a-icon",{staticClass:"edit_icon",attrs:{type:"edit"},nativeOn:{click:function(t){return t.stopPropagation(),e.linkInfo(a,a.bind?"1":"2")}}})],1):e._e()],1),t("div",{staticClass:"desc",attrs:{title:a.description}},[e._v(e._s(a.description||e.language.popover_empty_desc))])]),t("div",{staticClass:"setting_panel_item_right",attrs:{title:1==e.tabList.reduce((function(e,t){return[].concat(Object(i.a)(e),Object(i.a)(t.children))}),[]).filter((function(e){return e.bind})).length&&a.bind?void 0:e.language.popover_panel_title1}},[t("a-tooltip",{attrs:{title:1==e.tabList.reduce((function(e,t){return[].concat(Object(i.a)(e),Object(i.a)(t.children))}),[]).filter((function(e){return e.bind})).length&&a.bind?e.language.popover_panel_title2:void 0}},[t("a-switch",{attrs:{"checked-children":e.language.popover_panel_open,"un-checked-children":e.language.popover_panel_close,checked:a.bind,loading:a.bindLoading,disabled:1==e.tabList.reduce((function(e,t){return[].concat(Object(i.a)(e),Object(i.a)(t.children))}),[]).filter((function(e){return e.bind})).length&&a.bind},on:{change:function(t){return e.handleChangeBind(a,t)}}})],1)],1)])}))],2):e._e()]}))],2)])],1),t("a-tooltip",{attrs:{title:e.language.popover_title}},[t("div",{staticClass:"setting_icon"},[t("a-icon",{attrs:{type:"setting"}})],1)])],1)],1)],1),t("div",{staticClass:"arrow_box",style:{display:e.showArrow?"block":"none"},on:{click:e.scrollRight}},[t("a-icon",{attrs:{type:"right"}})],1)])]),t("a-spin",{staticStyle:{"min-height":"500px"},attrs:{spinning:e.loading,tip:e.language.panel_loading}},[t("grid-layout",{attrs:{layout:e.layout,"col-num":24,"row-height":30,"is-draggable":e.draggable,"is-resizable":e.resizable,"vertical-compact":!0,"use-css-transforms":!0},on:{"update:layout":function(t){e.layout=t}}},e._l(e.layout,(function(a){return t("grid-item",{key:a.unique,staticClass:"scroll_box",attrs:{static:a.static,x:a.x,y:a.y,w:a.w,h:a.h,i:a.i,minW:a.minW,minH:a.minH,maxW:a.maxW,maxH:a.maxH},on:{resize:e.resizeEvent}},["workbench_one"==a.unique?t("WorkbenchOne"):e._e(),"workbench_two"==a.unique?t("WorkbenchTwo",{attrs:{cardTitle:a.name}}):e._e(),"workbench_four"==a.unique?t("WorkbenchFour",{attrs:{cardTitle:a.name}}):e._e(),"resource_home_page_one"==a.unique?t("ResourceOne",{attrs:{cardTitle:a.name}}):e._e(),"resource_home_page_two"==a.unique?t("ResourceTwo",{attrs:{cardTitle:a.name}}):e._e(),"resource_home_page_three"==a.unique?t("ResourceThree",{attrs:{cardTitle:a.name}}):e._e(),"resource_home_page_four"==a.unique?t("ResourceFour",{attrs:{cardTitle:a.name}}):e._e(),"resource_home_page_seven"==a.unique?t("ResourceFive",{attrs:{cardTitle:a.name}}):e._e(),"resource_home_page_eight"==a.unique?t("ResourceSix",{attrs:{cardTitle:a.name}}):e._e(),"resource_home_page_five"==a.unique?t("ManagementCoverage",{attrs:{cardTitle:a.name}}):e._e(),"resource_home_page_six"==a.unique?t("Monitoring",{attrs:{cardTitle:a.name}}):e._e(),"resource_home_page_nine"==a.unique?t("Prom",{attrs:{cardTitle:a.name}}):(a.unique&&0===a.unique.indexOf("sec_")?t("SecurityOverviewCard",{attrs:{cardTitle:a.name,moduleType:a.unique.slice(4)}}):e._e())],1)})),1)],1)],1)}),[],!1,null,"9534a6fc",null);t.default=h.exports},"soc1":function(e,t,a){/* SecurityOverviewCard v6 — Beautified.
   - Card border-left 3px 主题色 (waf=红 / FW=蓝 / vuln=橙 / alert=紫 / host=青)
   - Top stats: 主指标 28px 加粗, 副指标 20px 彩色
   - 中部: 水平堆叠进度条 (替换原 donut 圆环)
   - TOP 列表: 序号 + 标签 + 占比 mini bar + 彩色数字
   - 配色: 严重 #cf1322 / 高 #ff4d4f / 中 #faad14 / 低 #52c41a / 信息 #8c8c8c / 主蓝 #1890ff
*/
(function(){
  if(!document.getElementById('sa-ov-style-v6')){
    var s=document.createElement('style');
    s.id='sa-ov-style-v6';
    s.textContent=[
      '.sa-ov-card{background:#fff;border:1px solid #f0f0f0;border-radius:6px;padding:11px 14px 12px;height:100%;box-sizing:border-box;display:flex;flex-direction:column;overflow:hidden;position:relative;}',
      '.sa-ov-card::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;}',
      '.sa-ov-card-waf::before{background:#ff4d4f;}',
      '.sa-ov-card-fw::before{background:#1890ff;}',
      '.sa-ov-card-vuln::before{background:#faad14;}',
      '.sa-ov-card-alert::before{background:#722ed1;}',
      '.sa-ov-card-host::before{background:#13c2c2;}',
      '.sa-ov-head{display:flex;justify-content:space-between;align-items:center;padding-bottom:7px;border-bottom:1px solid #f5f5f5;margin-bottom:10px;}',
      '.sa-ov-title{font-size:14px;font-weight:500;color:#262626;}',
      '.sa-ov-more{font-size:12px;color:#1890ff;cursor:pointer;text-decoration:none;}',
      '.sa-ov-more:hover{color:#40a9ff;}',
      '.sa-ov-stats{display:flex;align-items:baseline;gap:14px;margin-bottom:9px;}',
      '.sa-ov-stat-main{flex:1;min-width:0;}',
      '.sa-ov-stat-main-num{font-size:28px;font-weight:500;line-height:1.1;color:#262626;}',
      '.sa-ov-stat-sub{flex:0 0 auto;text-align:center;min-width:50px;}',
      '.sa-ov-stat-sub-num{font-size:20px;font-weight:500;line-height:1.1;}',
      '.sa-ov-stat-label{font-size:11px;color:#8c8c8c;margin-top:3px;}',
      '.sa-ov-bar-wrap{display:flex;height:6px;border-radius:3px;overflow:hidden;background:#f5f5f5;}',
      '.sa-ov-bar-seg{height:100%;}',
      '.sa-ov-legend{display:flex;flex-wrap:wrap;gap:3px 10px;margin-top:5px;font-size:11px;color:#595959;}',
      '.sa-ov-legend-item{display:flex;align-items:center;white-space:nowrap;}',
      '.sa-ov-legend-dot{width:7px;height:7px;border-radius:50%;margin-right:4px;display:inline-block;flex:0 0 auto;}',
      '.sa-ov-top{margin-top:auto;padding-top:8px;border-top:1px dashed #f0f0f0;}',
      '.sa-ov-top-head{font-size:11px;color:#8c8c8c;margin-bottom:5px;}',
      '.sa-ov-top-row{display:flex;align-items:center;font-size:11px;line-height:1.7;color:#595959;margin-bottom:1px;}',
      '.sa-ov-top-rank{color:#bfbfbf;width:14px;flex:0 0 auto;font-weight:500;}',
      '.sa-ov-top-label{flex:0 0 110px;padding-right:6px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}',
      '.sa-ov-top-bar{flex:1;height:4px;background:#f5f5f5;border-radius:2px;overflow:hidden;margin-right:6px;min-width:30px;}',
      '.sa-ov-top-bar-fill{display:block;height:100%;border-radius:2px;}',
      '.sa-ov-top-num{flex:0 0 auto;min-width:32px;text-align:right;font-weight:500;}',
      '.sa-ov-top-text{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;padding-right:6px;}',
      '.sa-ov-top-tag{display:inline-block;padding:0 5px;border-radius:2px;font-size:10px;line-height:14px;margin-right:6px;flex:0 0 auto;}',
      '.sa-ov-top-time{color:#8c8c8c;font-size:11px;flex:0 0 auto;}',
      '.sa-ov-top-msg{color:#faad14;font-size:10px;background:#fffbe6;padding:1px 5px;border-radius:2px;margin-left:6px;flex:0 0 auto;}',
      '.sa-ov-err{color:#f5222d;font-size:12px;margin-top:6px;}',
      '.sa-ov-empty{color:#bfbfbf;font-size:11px;text-align:center;padding:6px 0;}'
    ].join('');
    document.head.appendChild(s);
  }
})();

var SEV_COLORS_V6={'严重':'#cf1322','高':'#ff4d4f','中':'#faad14','低':'#52c41a','信息':'#8c8c8c','累计':'#8c8c8c','有事件':'#faad14','已恢复':'#52c41a','未分级':'#d9d9d9'};
var SEV_BG_V6={'高':'#fff1f0','中':'#fffbe6','低':'#f6ffed','严重':'#fff1f0'};

var SecurityOverviewCard={
  name:'SecurityOverviewCard',
  props:{ cardTitle:String, moduleType:String },
  data:function(){ return { loading:true, errMsg:'', stats:[], sev:[], topList:[], topMax:1, moreUrl:'' }; },
  created:function(){ this.load(); },
  methods:{
    load:function(){
      var self=this;
      var url='/t/esight/api/v1/control/v0_1/security-overview-'+self.moduleType+'/';
      fetch(url,{credentials:'include'}).then(function(r){return r.json();}).then(function(raw){
        self.loading=false;
        if(!raw||raw.code!==200){ self.errMsg=(raw&&raw.message)||'数据获取失败'; return; }
        var d=(raw&&raw.data)?raw.data:(raw||{});
        self.stats=self.buildStats(d);
        self.sev=self.buildSev(d);
        self.topList=self.buildTop(d);
        self.topMax=self.computeTopMax();
        self.moreUrl=self.buildMore();
      }).catch(function(){ self.loading=false; self.errMsg='加载失败'; });
    },
    buildStats:function(d){
      var T=d.totals||{}, out=[];
      if(this.moduleType==='waf'||this.moduleType==='fw'){
        out=[
          {label:'累计',value:T.total||0,color:'#262626'},
          {label:'今日',value:T.today||0,color:'#1890ff'},
          {label:'高危',value:T.high||0,color:(T.high||0)>0?'#ff4d4f':'#bfbfbf'}
        ];
      } else if(this.moduleType==='vuln'){
        out=[
          {label:'系统漏洞',value:T.sys_total||0,color:'#262626'},
          {label:'WEB漏洞',value:T.web_total||0,color:'#1890ff'},
          {label:'高危',value:T.high||0,color:(T.high||0)>0?'#ff4d4f':'#bfbfbf'}
        ];
      } else if(this.moduleType==='alert'){
        out=[
          {label:'规则总数',value:T.total||0,color:'#262626'},
          {label:'今日扫描',value:T.today||0,color:'#1890ff'},
          {label:'已恢复',value:T.scans_with_resolved||0,color:'#52c41a'}
        ];
      } else if(this.moduleType==='host'){
        out=[
          {label:'主机总数',value:T.total||0,color:'#262626'},
          {label:'SSH正常',value:T.ssh_normal||0,color:'#1890ff'},
          {label:'SNMP正常',value:T.snmp_normal||0,color:'#52c41a'}
        ];
      }
      return out;
    },
    buildSev:function(d){
      var self=this;
      if(self.moduleType==='waf'||self.moduleType==='fw'||self.moduleType==='vuln'){
        var sd=d.severity_dist||[];
        if(sd.length===0) return [];
        return sd.map(function(x){ return { name:x.name, value:x.value, color:SEV_COLORS_V6[x.name]||'#bfbfbf' }; });
      } else if(self.moduleType==='alert'){
        var T=d.totals||{};
        return [
          {name:'累计',value:T.total||0,color:'#8c8c8c'},
          {name:'有事件',value:T.scans_with_event||0,color:'#faad14'},
          {name:'已恢复',value:T.scans_with_resolved||0,color:'#52c41a'}
        ];
      } else if(self.moduleType==='host'){
        var md=d.monitor_dist||[];
        var palette=['#1890ff','#52c41a','#faad14','#722ed1','#13c2c2'];
        return md.map(function(x,i){ return { name:x.name, value:x.value, color:palette[i%palette.length] }; });
      }
      return [];
    },
    buildTop:function(d){
      var self=this, list=[];
      if(self.moduleType==='waf'||self.moduleType==='fw'){
        (d.top_src_ip||[]).slice(0,4).forEach(function(it){
          list.push({kind:'src',label:it.label||it.src_ip||'?',count:it.count||0});
        });
      } else if(self.moduleType==='vuln'){
        (d.top_vulns||[]).slice(0,4).forEach(function(it){
          list.push({
            kind:'vuln',
            label:it.label||it.name||'?',
            count:it.count||0,
            severity:it.severity||((it.count||0)>=5?'高':((it.count||0)>=2?'中':'低'))
          });
        });
      } else if(self.moduleType==='alert'){
        list.push({kind:'alert-event',latest:d.latest||null});
      } else if(self.moduleType==='host'){
        (d.err_hosts||[]).slice(0,4).forEach(function(it){
          list.push({kind:'host',label:it.label||'?',msg:it.msg||''});
        });
      }
      return list;
    },
    computeTopMax:function(){
      var m=1;
      (this.topList||[]).forEach(function(it){
        if(it && typeof(it.count)==='number' && it.count>m) m=it.count;
      });
      return m;
    },
    buildMore:function(){
      var map={waf:'/security/wafMonitor',fw:'/security/fwMonitor',vuln:'/security/vscanMonitor',alert:'/security/securityAlert',host:'/network/hostMonitor'};
      var path=map[this.moduleType]||'/';
      return window.location.origin+'/t/esight/#'+path;
    },
    fmtNum:function(n){
      n=Number(n)||0;
      return String(n).replace(/\B(?=(\d{3})+(?!\d))/g,',');
    },
    sevTotal:function(){
      var t=0;
      (this.sev||[]).forEach(function(s){ t+=(s.value||0); });
      return t;
    },
    renderBar:function(h){
      var segs=this.sev||[];
      var total=this.sevTotal();
      var nodes;
      if(total>0 && segs.length>0){
        nodes=segs.map(function(s){
          var pct=((s.value||0)/total)*100;
          return h('div',{staticClass:'sa-ov-bar-seg',style:{width:pct+'%',background:s.color||'#bfbfbf'}});
        });
      } else {
        nodes=[h('div',{staticClass:'sa-ov-bar-seg',style:{width:'100%',background:'#e8e8e8'}})];
      }
      return h('div',{staticClass:'sa-ov-bar-wrap'},nodes);
    },
    renderLegend:function(h){
      var self=this;
      var items=(this.sev||[]).map(function(s){
        return h('div',{staticClass:'sa-ov-legend-item'},[
          h('span',{staticClass:'sa-ov-legend-dot',style:{background:s.color||'#bfbfbf'}}),
          h('span',[(s.name||'')+' '+(s.value||0)])
        ]);
      });
      if(items.length===0){
        items=[h('div',{staticClass:'sa-ov-empty'},['暂无分级数据'])];
      }
      return h('div',{staticClass:'sa-ov-legend'},items);
    },
    renderTop:function(h){
      var self=this;
      var items=this.topList||[];
      if(items.length===0) return h('div',{staticClass:'sa-ov-top'},[
        h('div',{staticClass:'sa-ov-top-head'},[h('span',['TOP 详情'])]),
        h('div',{staticClass:'sa-ov-empty'},['暂无数据'])
      ]);

      // alert: 单一最新事件卡片
      if(this.moduleType==='alert'){
        var latest=items[0]&&items[0].latest;
        var head=h('div',{staticClass:'sa-ov-top-head'},[h('span',['最新扫描事件'])]);
        var body;
        if(!latest){
          body=h('div',{staticClass:'sa-ov-empty'},['暂无新事件']);
        } else {
          body=h('div',{staticClass:'sa-ov-top-row'},[
            h('span',{staticClass:'sa-ov-top-tag',style:{background:'#fff1f0',color:'#ff4d4f'}},['新增']),
            h('span',{staticClass:'sa-ov-top-time'},[latest.scan_time||'']),
            h('span',{staticClass:'sa-ov-top-text'},['新增 '+(latest.events_new||0)+' 条事件'])
          ]);
        }
        return h('div',{staticClass:'sa-ov-top'},[head,body]);
      }

      var headTitle='';
      if(this.moduleType==='waf') headTitle='TOP 攻击源 IP（当日）';
      else if(this.moduleType==='fw') headTitle='TOP 来源 IP（当日）';
      else if(this.moduleType==='vuln') headTitle='TOP 高危漏洞';
      else if(this.moduleType==='host') headTitle='异常主机';
      var head=h('div',{staticClass:'sa-ov-top-head'},[h('span',[headTitle])]);

      var rows=items.slice(0,4).map(function(it,idx){
        if(it.kind==='vuln'){
          var sevC=SEV_COLORS_V6[it.severity]||'#faad14';
          var sevBg=SEV_BG_V6[it.severity]||'#fafafa';
          return h('div',{staticClass:'sa-ov-top-row'},[
            h('span',{staticClass:'sa-ov-top-rank'},[String(idx+1)]),
            h('span',{staticClass:'sa-ov-top-tag',style:{background:sevBg,color:sevC}},[it.severity||'中']),
            h('span',{staticClass:'sa-ov-top-text'},[it.label]),
            h('span',{staticClass:'sa-ov-top-num',style:{color:sevC}},['×'+(it.count||0)])
          ]);
        } else if(it.kind==='host'){
          return h('div',{staticClass:'sa-ov-top-row'},[
            h('span',{staticClass:'sa-ov-top-rank'},[String(idx+1)]),
            h('span',{staticClass:'sa-ov-top-text'},[it.label]),
            it.msg?h('span',{staticClass:'sa-ov-top-msg'},[it.msg]):null
          ]);
        } else {
          // waf/fw src IP: 序号 + IP + mini bar + count
          var pct=self.topMax>0?((it.count||0)/self.topMax)*100:0;
          var color=(self.moduleType==='waf')?'#ff4d4f':'#1890ff';
          return h('div',{staticClass:'sa-ov-top-row'},[
            h('span',{staticClass:'sa-ov-top-rank'},[String(idx+1)]),
            h('span',{staticClass:'sa-ov-top-label'},[it.label]),
            h('span',{staticClass:'sa-ov-top-bar'},[
              h('span',{staticClass:'sa-ov-top-bar-fill',style:{width:pct+'%',background:color}})
            ]),
            h('span',{staticClass:'sa-ov-top-num',style:{color:color}},[self.fmtNum(it.count)])
          ]);
        }
      });
      return h('div',{staticClass:'sa-ov-top'},[head,h('div',{},rows)]);
    }
  },
  render:function(h){
    var self=this;
    var header=h('div',{staticClass:'sa-ov-head'},[
      h('span',{staticClass:'sa-ov-title'},[self.cardTitle||'']),
      h('a',{staticClass:'sa-ov-more',attrs:{href:self.moreUrl,target:'_blank'}},['查看更多 ›'])
    ]);
    var statNodes=(self.stats||[]).map(function(s,idx){
      var mainClass=idx===0?'sa-ov-stat-main':'sa-ov-stat-sub';
      var numClass=idx===0?'sa-ov-stat-main-num':'sa-ov-stat-sub-num';
      return h('div',{staticClass:mainClass},[
        h('div',{staticClass:numClass,style:{color:s.color||'#262626'}},[self.fmtNum(s.value)]),
        h('div',{staticClass:'sa-ov-stat-label'},[s.label])
      ]);
    });
    var statsRow=h('div',{staticClass:'sa-ov-stats'},statNodes);
    var bar=self.renderBar(h);
    var legend=self.renderLegend(h);
    var top=self.renderTop(h);
    var bodyChildren=[statsRow,bar,legend,top];
    if(self.errMsg){ bodyChildren.push(h('div',{staticClass:'sa-ov-err'},[self.errMsg])); }
    return h('div',{staticClass:'sa-ov-card sa-ov-card-'+(self.moduleType||'')},[header].concat(bodyChildren));
  }
};
t.__esModule=true;
t.default=SecurityOverviewCard;},a00f:function(e,t,a){"use strict";a("a4d0")},a4d0:function(e,t,a){}}]);