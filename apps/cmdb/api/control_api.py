# -*- coding: utf-8 -*-
"""
eSight Control API 转发层 — 把 control 前端（直接搬运的 control dist）请求落到本地 view

control 的前端 dist 在 baseURL 用 /api/control/v0_1/... 访问，eSight 把它转到本地实现：
  - 网络设备相关接口：转发到 apps.cmdb.api.network_views 中已实现的 view
  - 其他接口：返回占位响应（200 + 空数据），让前端不崩

注意：control 路由有 ~200 个 endpoint，本期只实现关键的网络设备模块；其余先用 stub 兜底。
"""
import json
import logging
import re
import requests as _req
from django.conf import settings as _settings
from django.http import JsonResponse

logger = logging.getLogger('app')


def _proxy_platform_api(request, platform_path):
    """把请求转发到 OpsAny 管控平台对应 endpoint，返回 JSON
    用于 user_info / get-menu / home-page-* / auth-* 等 control 前端启动/概览必调的接口，
    eSight 直接透传平台真实数据（平台共享基础设施，无需自己造数据）。
    """
    url = 'https://{}/o/control/api/control/v0_1/{}'.format(
        str(getattr(_settings, 'BK_URL', '192.168.99.31')).rstrip('/').replace('https://', '').replace('http://', ''),
        platform_path,
    )
    bk_token = request.COOKIES.get('bk_token') or request.COOKIES.get('sessionid') or ''
    try:
        # ⚠️ 2026-08-13 修复：必须透传 request.GET（如 home-page-show/?id=1），
        # 否则平台按"无参"返回全量面板数组，前端 data.card_list.map 崩溃 → 概览内容区空白。
        # 同时按请求 method 转发（部分接口是 POST，如 home-page-reset / home-page-setting）。
        common = dict(params=request.GET, cookies={'bk_token': bk_token}, timeout=20, verify=False)
        if request.method == 'POST':
            headers = {'Content-Type': request.content_type or 'application/json'}
            r = _req.post(url, data=request.body, headers=headers, **common)
        else:
            r = _req.get(url, **common)
        if r.status_code == 200:
            try:
                payload = r.json()
            except Exception:
                payload = {'code': 50000, 'message': '平台返回非 JSON', 'data': None}
            # 关闭平台水印（user_info 返回 watermark_enable: true 会全屏铺用户名水印）
            if isinstance(payload, dict) and isinstance(payload.get('data'), dict):
                payload['data']['watermark_enable'] = False
            return JsonResponse(payload)
        return JsonResponse({'code': 50000, 'message': '平台转发失败 HTTP {}'.format(r.status_code), 'data': None})
    except Exception as e:
        logger.warning('[proxy_platform] %s error: %s', platform_path, e)
        return JsonResponse({'code': 50000, 'message': '平台认证转发失败: {}'.format(e), 'data': None})


def ok(data=None, msg='信息获取成功'):
    if data is None:
        data = {}
    return JsonResponse({'code': 200, 'successcode': 20005, 'message': msg, 'data': data})


def stub_view(request, *args, **kwargs):
    """未实现接口的占位：返回 200 + 空 data（前端组件按空状态渲染）

    �️ 2026-08-13 关键修复：默认 data=[] 而非 {}。
    control dist 中大量接口（如 controller-zabbix-group / prometheus-group / network-equipment-type-v2）
    在 then 回调里执行 `e.data.map(...)`，如果 data={} 会抛 `e.data.map is not a function`，
    导致页面 JS 崩溃（用户报告"页面打不开"）。
    数组是更通用的 fallback：`.map/.forEach/.filter` 都安全；少数期望 dict 的接口必须真实实现。
    """
    path = request.path
    logger.info('[control_stub] %s %s', request.method, path)
    return JsonResponse({'code': 200, 'successcode': 20005, 'message': '信息获取成功', 'data': []})


def control_api_router(request, path=''):
    """/api/control/v0_1/<path> — 按 path 路由到对应 view，未匹配则 stub"""
    path = path.rstrip('/')
    # 长前缀优先匹配
    for prefix, view_fn in sorted(CONTROL_API_MAP.items(), key=lambda kv: -len(kv[0])):
        if path == prefix.rstrip('/') or path.startswith(prefix):
            try:
                return view_fn(request)
            except Exception as e:
                logger.exception('[control_api] %s error: %s', path, e)
                return JsonResponse({'code': 50000, 'message': f'服务异常: {e}', 'data': None})
    # 未实现：返回空数据 stub
    return stub_view(request)


# ─────────────── 网络设备模块（直接调本地 view 函数）─────────────────
def network_equipment_all_proxy(request):
    """GET /api/control/v0_1/network-equipment-all/ — 设备列表"""
    from apps.cmdb.api.network_views import NetworkEquipmentAllView
    return NetworkEquipmentAllView.as_view()(request)


def network_equipment_proxy(request):
    """POST/PUT/DELETE /api/control/v0_1/network-equipment/ — 设备 CRUD"""
    from apps.cmdb.api.network_views import NetworkEquipmentView
    return NetworkEquipmentView.as_view()(request)


def network_equipment_info_proxy(request):
    """GET /api/control/v0_1/network-equipment-info/ — 设备详情"""
    from apps.cmdb.api.network_views import NetworkEquipmentInfoView
    return NetworkEquipmentInfoView.as_view()(request)


def network_equipment_test_proxy(request):
    """POST /api/control/v0_1/network-equipment-test/ — 连接测试"""
    from apps.cmdb.api.network_views import NetworkEquipmentTestView
    return NetworkEquipmentTestView.as_view()(request)


def network_equipment_ping_proxy(request):
    """POST /api/control/v0_1/network-equipment-ping/ — 批量 ping"""
    from apps.cmdb.api.network_views import NetworkEquipmentPingView
    return NetworkEquipmentPingView.as_view()(request)


def network_equipment_flush_proxy(request):
    """POST /api/control/v0_1/network-equipment-flush/ — 同步设备"""
    from apps.cmdb.api.network_views import NetworkEquipmentFlushView
    return NetworkEquipmentFlushView.as_view()(request)


def network_equipment_flush_v2_proxy(request):
    """GET /api/control/v0_1/network-equipment-flush-v2/ — 实时采集 sys_log + cpu_mem（详情页自动调）"""
    from apps.cmdb.api.network_views import NetworkEquipmentFlushV2View
    return NetworkEquipmentFlushV2View.as_view()(request)


def network_config_diff_proxy(request):
    """GET /api/control/v0_1/network-config-diff/ — 配置对比"""
    from apps.cmdb.api.network_views import NetworkConfigDiffView
    return NetworkConfigDiffView.as_view()(request)


def network_pull_config_proxy(request):
    """GET /api/control/v0_1/network-pull-config/ — 拉取设备配置"""
    from apps.cmdb.api.network_views import NetworkPullConfigView
    return NetworkPullConfigView.as_view()(request)


def network_type_proxy(request):
    """GET /api/control/v0_1/network-type/ — 设备类型"""
    from apps.cmdb.api.network_views import NetworkTypeView
    return NetworkTypeView.as_view()(request)


def network_equipment_type_v2_proxy(request):
    """GET /api/control/v0_1/network-equipment-type-v2/ — 厂商品牌"""
    from apps.cmdb.api.network_views import NetworkEquipmentTypeV2View
    return NetworkEquipmentTypeV2View.as_view()(request)


def network_group_proxy(request):
    """GET/POST/PUT/DELETE /api/control/v0_1/network-group/ — 设备分组"""
    from apps.cmdb.api.network_views import NetworkGroupView
    return NetworkGroupView.as_view()(request)


def controller_proxy(request):
    """GET /api/control/v0_1/controller/ — 控制器列表"""
    from apps.cmdb.api.network_views import ControllerView
    return ControllerView.as_view()(request)


def get_network_proxy(request):
    """GET /api/control/v0_1/get-network/ — 从 CMDB 拉设备（v2 占位）"""
    from apps.cmdb.api.network_views import GetNetworkView
    return GetNetworkView.as_view()(request)


# ─────────────── home-page 概览（control Dashboard）───────────────────
def home_page_card_proxy(request):
    """GET /api/control/v0_1/home-page-card/ — 概览卡片（直接转发平台拿正确 panel_group/data_list 格式）"""
    return _proxy_platform_api(request, 'home-page-card/')


def home_page_analyze_proxy(request):
    """GET /api/control/v0_1/home-page-network-analyze/ — 网络设备类型分布（转发平台）"""
    return _proxy_platform_api(request, 'home-page-network-analyze/')


def home_page_alarm_trend_proxy(request):
    """GET /api/control/v0_1/alarm-trend/ — 告警趋势（转发平台）"""
    return _proxy_platform_api(request, 'alarm-trend/')


def home_page_show_proxy(request):
    """GET /api/control/v0_1/home-page-show/ — 首页面板（含 tabList，转发平台拿真实 PanelInst）"""
    return _proxy_platform_api(request, 'home-page-show/')



def user_info_proxy(request):
    """GET /user_info/ — 转发到平台 user_info（control 前端实际请求 user_info/ 下划线形式）"""
    return _proxy_platform_api(request, 'user_info/')


def get_menu_proxy(request):
    """GET /get-menu/ — 转发到平台 get-menu（control 前端左侧菜单树来自此接口）
    ⚠️ 2026-08-14 v2：仅改「主机管理」显示名为「主机监控」（menu_code/menu_address 不动，
    前端权限校验依赖 menu_code，改动 menu_code 会导致页面"未授权"——v1 事故教训）。
    点击行为由 templates/index.html 注入脚本拦截（SPA 内渲染大屏 iframe）。
    """
    from django.http import JsonResponse
    resp = _proxy_platform_api(request, 'get-menu/')
    try:
        import json
        content = json.loads(resp.content)
        if content.get('code') == 200 and isinstance(content.get('data'), dict):
            data = content['data']

            def _patch(node):
                # ⚠️ 照搬 control 其他菜单的机制：menu_code 对应前端组件映射表 v[code]（已 patch 加 hostMonitor/wafMonitor），
                # menu_address 是 SPA 路由 path。这样「主机监控」「网络安全设备监控」就是真正的 SPA 路由。
                if node.get('id') == 47 or node.get('menu_code') == 'node':
                    node['menu_name'] = '主机监控'
                    node['show_name'] = '主机监控'
                    node['menu_code'] = 'hostMonitor'
                    node['menu_address'] = '/network/hostMonitor'
                # 2026-08-17：WAF 攻击日志——在「资源纳管」下「主机监控」前插入同级菜单
                if node.get('id') == 46 or node.get('menu_code') == 'group':
                    children = node.setdefault('children', [])
                    if not any(m.get('menu_code') == 'wafMonitor' for m in children):
                        children.insert(0, {
                            'id': 900001, 'menu_name': 'WAF攻击日志', 'show_name': 'WAF攻击日志',
                            'priority': '3.2.2', 'menu_code': 'wafMonitor', 'menu_address': '/security/wafMonitor',
                            'parent_id': node.get('id'), 'menu_type': 'menu', 'display': 1,
                            'children': [], 'auth': [],
                        })
                    else:
                        for m in children:
                            if m.get('menu_code') == 'wafMonitor':
                                m['menu_name'] = 'WAF攻击日志'
                                m['show_name'] = 'WAF攻击日志'
                    # 2026-08-17：防火墙日志（华为 USG6625F）——WAF攻击日志后插入
                    if not any(m.get('menu_code') == 'fwMonitor' for m in children):
                        idx = next((i for i, m in enumerate(children) if m.get('menu_code') == 'wafMonitor'), 0) + 1
                        children.insert(idx, {
                            'id': 900002, 'menu_name': '防火墙日志', 'show_name': '防火墙日志',
                            'priority': '3.2.3', 'menu_code': 'fwMonitor', 'menu_address': '/security/fwMonitor',
                            'parent_id': node.get('id'), 'menu_type': 'menu', 'display': 1,
                            'children': [], 'auth': [],
                        })
                for c in (node.get('children') or []):
                    _patch(c)

            if 'children' in data:
                for n in data['children']:
                    _patch(n)
            return JsonResponse(content)
    except Exception:
        pass
    return resp


def auth_login_proxy(request):
    """POST /auth/login/ — control 平台共享 OpsAny 会话，此处返回已登录状态"""
    return JsonResponse({'code': 200, 'successcode': 20000, 'message': '已登录', 'data': {}})


def auth_logout_proxy(request):
    """POST /auth/logout/ — 转发到平台 logout"""
    return _proxy_platform_api(request, 'logout/')


def controller_salt_ping(request):
    """POST /api/v1/control/v0_1/controller-salt/ — 控制器连通性测试（eSight → opsany-paas-proxy /ht/）"""
    from apps.cmdb.api.network_views import ControllerSaltPingView
    return ControllerSaltPingView.as_view()(request)


def controller_salt_status(request):
    """GET /api/v1/control/v0_1/controller-salt-status/ — 控制器状态（心跳检查）"""
    from apps.cmdb.api.network_views import ControllerSaltStatusView
    return ControllerSaltStatusView.as_view()(request)


def controller_test(request):
    """POST /api/v1/control/v0_1/controller-test/ — 控制器测试（control dist 编辑器的"测试"按钮）"""
    from apps.cmdb.api.network_views import ControllerTestView
    return ControllerTestView.as_view()(request)


def _controller_ping_proxy(request):
    """POST /api/v1/control/v0_1/controller-ping/ — 连接测试（control dist 新建/编辑弹窗按钮）"""
    from apps.cmdb.api.network_views import ControllerPingView
    return ControllerPingView.as_view()(request)


def _update_controller_status_proxy(request):
    """GET /api/v1/control/v0_1/update-controller-status/ — 刷新状态（control dist 刷新按钮）"""
    from apps.cmdb.api.network_views import UpdateControllerStatusView
    return UpdateControllerStatusView.as_view()(request)


# ─────────────── URL 映射（control 路径 → 本地视图函数）────────────────
CONTROL_API_MAP = {
    # 网络设备（已本地实现）
    'network-equipment-all/': network_equipment_all_proxy,
    'network-equipment/': network_equipment_proxy,
    'network-equipment-info/': network_equipment_info_proxy,
    'network-equipment-test/': network_equipment_test_proxy,
    'network-equipment-ping/': network_equipment_ping_proxy,
    'network-equipment-flush/': network_equipment_flush_proxy,
    'network-equipment-flush-v2/': network_equipment_flush_v2_proxy,
    'network-config-diff/': network_config_diff_proxy,
    'network-pull-config/': network_pull_config_proxy,
    'network-equipment-type-v2/': network_equipment_type_v2_proxy,
    'network-type/': network_type_proxy,
    'network-group/': network_group_proxy,
    'controller/': controller_proxy,
    'controller-salt/': controller_salt_ping,
    'controller-salt-status/': controller_salt_status,
    'controller-test/': controller_test,
    'controller-ping/': lambda r: _controller_ping_proxy(r),
    'update-controller-status/': lambda r: _update_controller_status_proxy(r),
    'get-network/': get_network_proxy,
    # 概览（control Dashboard）— 全部转发平台拿真实结构（前端对这些接口有严格字段要求）
    'home-page-card/': home_page_card_proxy,
    'home-page-show/': home_page_show_proxy,
    'home-page-network-analyze/': home_page_analyze_proxy,
    'home-page-agent-control-type-analyze/': lambda r: _proxy_platform_api(r, 'home-page-agent-control-type-analyze/'),
    'home-page-agent-host-type-analyze/': lambda r: _proxy_platform_api(r, 'home-page-agent-host-type-analyze/'),
    'home-page-analyze-index/': home_page_analyze_proxy,
    'home-page-database-analyze/': lambda r: _proxy_platform_api(r, 'home-page-database-analyze/'),
    'home-page-middleware-analyze/': lambda r: _proxy_platform_api(r, 'home-page-middleware-analyze/'),
    'home-page-duty/': lambda r: _proxy_platform_api(r, 'home-page-duty/'),
    'home-page-inst/': lambda r: _proxy_platform_api(r, 'home-page-inst/'),
    'home-page-receipts/': lambda r: _proxy_platform_api(r, 'home-page-receipts/'),
    'home-page-resource-manage/': lambda r: _proxy_platform_api(r, 'home-page-resource-manage/'),
    'home-page-reset/': lambda r: _proxy_platform_api(r, 'home-page-reset/'),
    'home-page-setting/': lambda r: _proxy_platform_api(r, 'home-page-setting/'),
    'home-page-user-message/': lambda r: _proxy_platform_api(r, 'home-page-user-message/'),
    # 前端消息角标/顶部导航/版权（control dist 启动必调）
    'get-user-message/': lambda r: _proxy_platform_api(r, 'get-user-message/'),
    'get-nav-and-collection/': lambda r: _proxy_platform_api(r, 'get-nav-and-collection/'),
    'copyright-config/': lambda r: _proxy_platform_api(r, 'copyright-config/'),
    'alarm-trend/': home_page_alarm_trend_proxy,
    # control 前端启动时必调：用户信息 + 左侧菜单树（转发到平台，拿真实数据）
    'user_info/': user_info_proxy,
    'get-menu/': get_menu_proxy,
    # control dist 硬编码的绝对路径（baseURL 拼接后会落到 catch-all，平台转发）
    'auth/login/': auth_login_proxy,
    'auth/logout/': auth_logout_proxy,
    'user/info/': user_info_proxy,
    # ─── IP 地址管理（本地落库，v2）───
    'subnet-mask-scan-state/': lambda r: _ipm('subnet_mask_scan_state_view', r),
    'subnet-mask-scan/': lambda r: _ipm('subnet_mask_scan_view', r),
    'subnet-mask/': lambda r: _ipm('subnet_mask_view', r),
    'ip-port-scan-result/': lambda r: _ipm('ip_port_scan_result_view', r),
    'ip-port-scan/': lambda r: _ipm('ip_port_scan_view', r),
    'ip-overview/': lambda r: _ipm('ip_overview_view', r),
    'ip-address/': lambda r: _ipm('ip_address_view', r),
    'ip-manager-group/': lambda r: _ipm('ip_manager_group_view', r),
    'ip-manager/': lambda r: _ipm('ip_manager_view', r),
}


def _ipm(view_name, request):
    """IP 管理视图分发（延迟 import，避免循环依赖）"""
    from apps.cmdb.api.ip_management_views import (
        subnet_mask_view, ip_manager_group_view, ip_manager_view,
        ip_address_view, ip_overview_view, subnet_mask_scan_view,
        subnet_mask_scan_state_view, ip_port_scan_view, ip_port_scan_result_view,
    )
    _MAP = {
        'subnet_mask_view': subnet_mask_view,
        'ip_manager_group_view': ip_manager_group_view,
        'ip_manager_view': ip_manager_view,
        'ip_address_view': ip_address_view,
        'ip_overview_view': ip_overview_view,
        'subnet_mask_scan_view': subnet_mask_scan_view,
        'subnet_mask_scan_state_view': subnet_mask_scan_state_view,
        'ip_port_scan_view': ip_port_scan_view,
        'ip_port_scan_result_view': ip_port_scan_result_view,
    }
    return _MAP[view_name](request)
