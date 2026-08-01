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
]
