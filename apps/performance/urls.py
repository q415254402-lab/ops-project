from django.conf.urls import url, include
from rest_framework.routers import DefaultRouter
from apps.performance.api.perf_views import (
    MetricDefinitionViewSet, CollectTaskViewSet,
    MetricThresholdViewSet, MetricDataViewSet,
)

router = DefaultRouter()
router.register(r'metrics', MetricDefinitionViewSet)
router.register(r'tasks', CollectTaskViewSet)
router.register(r'thresholds', MetricThresholdViewSet)
router.register(r'data', MetricDataViewSet, basename='metric-data')

urlpatterns = [url(r'^', include(router.urls))]
