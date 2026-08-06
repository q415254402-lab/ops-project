from django.urls import re_path, include
from rest_framework.routers import DefaultRouter
from apps.topology.api.topology_views import TopologyMapViewSet, DiscoveryTaskViewSet

router = DefaultRouter()
router.register(r'maps', TopologyMapViewSet)
router.register(r'discovery', DiscoveryTaskViewSet)

urlpatterns = [re_path(r'^', include(router.urls))]
