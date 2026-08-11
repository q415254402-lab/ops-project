"""
CMDB URL 路由
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
from .api.platform_views import (
    NetworkEquipmentListProxy, NetworkFromCMDBProxy,
    NetworkEquipmentTestProxy, NetworkEquipmentPingProxy,
    NetworkEquipmentSaveProxy, NetworkEquipmentDeleteProxy, NetworkEquipmentFlushProxy,
    EquipmentTypeProxy, NetworkTypeProxy, NetworkGroupProxy, ZcModelProxy,
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
    # ── 平台管控薄代理（转发到 OpsAny control，设备/厂商/类型只读平台）──
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
]
