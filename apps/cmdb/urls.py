"""
CMDB URL 路由
- /cmdb/...：本地 CMDB（保留）
- /cmdb/platform/...：旧薄代理（已废弃，前端不再调用）
- /cmdb/network/...：本地复刻 control 网络设备模块（v2 主路径）
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .api.device_views import (
    DeviceViewSet, DeviceTypeViewSet,
    DeviceModelViewSet, ManufacturerViewSet,
)
from .api.resource_views import (
    RoomViewSet, CabinetViewSet, VlanViewSet,
    IPAddressViewSet, CredentialViewSet, InterfaceViewSet,
)
from .api.network_views import (
    NetworkTypeView, NetworkEquipmentTypeV2View, NetworkGroupView,
    NetworkEquipmentAllView, NetworkEquipmentView, NetworkEquipmentInfoView,
    NetworkEquipmentTestView, NetworkEquipmentPingView, NetworkEquipmentFlushView,
    ControllerView, GetNetworkView,
)
from .api.control_api import control_api_router
from .api.host_monitor_api import (
    HostListProxyView, HostGroupsProxyView, ControllerListProxyView,
    HostDetailProxyView, HostRelationsProxyView,
    ZabbixMetricsView, ZabbixRealtimeView, ZabbixHostStatusView,
    ZabbixAlarmsView, ZabbixPingView, HostMonitorConfigView,
)
from .api.waf_views import WafLogsView, WafStatsView
from .api.platform_views import (
    NetworkEquipmentListProxy, NetworkFromCMDBProxy,
    NetworkEquipmentTestProxy, NetworkEquipmentPingProxy,
    NetworkEquipmentSaveProxy, NetworkEquipmentDeleteProxy, NetworkEquipmentFlushProxy,
    EquipmentTypeProxy, NetworkTypeProxy, NetworkGroupProxy, ZcModelProxy, ControllerProxy,
)

router = DefaultRouter()
router.register(r'devices', DeviceViewSet)
router.register(r'device-types', DeviceTypeViewSet)
router.register(r'device-models', DeviceModelViewSet)
router.register(r'manufacturers', ManufacturerViewSet)
# 资源管理
router.register(r'rooms', RoomViewSet)
router.register(r'cabinets', CabinetViewSet)
router.register(r'vlans', VlanViewSet)
router.register(r'ip-addresses', IPAddressViewSet)
router.register(r'credentials', CredentialViewSet)
router.register(r'interfaces', InterfaceViewSet)

urlpatterns = [
    path('', include(router.urls)),
    # ── v2 网络设备模块（本地复刻 control，完全本地落库）──
    path('network/network-type/', NetworkTypeView.as_view()),
    path('network/network-equipment-type-v2/', NetworkEquipmentTypeV2View.as_view()),
    path('network/network-group/', NetworkGroupView.as_view()),
    path('network/network-equipment-all/', NetworkEquipmentAllView.as_view()),
    path('network/network-equipment/', NetworkEquipmentView.as_view()),
    path('network/network-equipment-info/', NetworkEquipmentInfoView.as_view()),
    path('network/network-equipment-test/', NetworkEquipmentTestView.as_view()),
    path('network/network-equipment-ping/', NetworkEquipmentPingView.as_view()),
    path('network/network-equipment-flush/', NetworkEquipmentFlushView.as_view()),
    path('network/controller/', ControllerView.as_view()),
    path('network/get-network/', GetNetworkView.as_view()),

    # ── 旧薄代理（保留兼容，新前端不再调用）──
    path('platform/network-equipments/', NetworkEquipmentListProxy.as_view()),
    path('platform/network-equipment/', NetworkEquipmentSaveProxy.as_view()),
    path('platform/network-equipment-delete/', NetworkEquipmentDeleteProxy.as_view()),
    path('platform/network-equipment-flush/', NetworkEquipmentFlushProxy.as_view()),
    path('platform/network-from-cmdb/', NetworkFromCMDBProxy.as_view()),
    path('platform/network-equipment-test/', NetworkEquipmentTestProxy.as_view()),
    path('platform/network-equipment-ping/', NetworkEquipmentPingProxy.as_view()),
    path('platform/equipment-type-v2/', EquipmentTypeProxy.as_view()),
    path('platform/network-type/', NetworkTypeProxy.as_view()),
    path('platform/network-group/', NetworkGroupProxy.as_view()),
    path('platform/zc-model/', ZcModelProxy.as_view()),
    path('platform/controller/', ControllerProxy.as_view()),
    # ── v5 主机监控大屏（2026-08-14）──
    path('host-monitor/host-list/', HostListProxyView.as_view()),
    path('host-monitor/config/', HostMonitorConfigView.as_view()),
    path('host-monitor/host-groups/', HostGroupsProxyView.as_view()),
    path('host-monitor/controller-list/', ControllerListProxyView.as_view()),
    path('host-monitor/host-detail/', HostDetailProxyView.as_view()),
    path('host-monitor/host-relations/', HostRelationsProxyView.as_view()),
    path('host-monitor/zabbix/metrics/', ZabbixMetricsView.as_view()),
    path('host-monitor/zabbix/realtime/', ZabbixRealtimeView.as_view()),
    path('host-monitor/zabbix/host-status/', ZabbixHostStatusView.as_view()),
    path('host-monitor/zabbix/alarms/', ZabbixAlarmsView.as_view()),
    path('host-monitor/zabbix/ping/', ZabbixPingView.as_view()),
    # ── v6 网络安全设备监控：WAF 攻击日志（2026-08-17）──
    path('waf/logs/', WafLogsView.as_view()),
    path('waf/stats/', WafStatsView.as_view()),
    # ── v4 直接搬运 control 前端 dist（baseURL = /t/esight/api/v1/control/v0_1/...）──
    # 控制 dist 会请求 ~200 个 endpoint，eSight 实现核心网络设备 + 概览 dashboard，
    # 其他 endpoint 由 control_api_router 兜底返回空数据避免前端崩
    path('control/v0_1/<path:path>', control_api_router),
]
