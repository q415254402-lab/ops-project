from django.urls import re_path, include
from rest_framework.routers import DefaultRouter
from apps.performance.api.perf_views import (
    MetricDefinitionViewSet, CollectTaskViewSet,
    MetricThresholdViewSet, MetricDataViewSet, InterfaceTrafficViewSet,
)

router = DefaultRouter()
router.register(r'metrics', MetricDefinitionViewSet)
router.register(r'tasks', CollectTaskViewSet)
router.register(r'thresholds', MetricThresholdViewSet)
router.register(r'data', MetricDataViewSet, basename='metric-data')
router.register(r'interface-traffic', InterfaceTrafficViewSet, basename='interface-traffic')

urlpatterns = [re_path(r'^', include(router.urls))]
