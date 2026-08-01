# -*- coding: utf-8 -*-
from django.conf.urls import url, include
from rest_framework.routers import DefaultRouter

from apps.discovery.api.discovery_views import DiscoveryTaskViewSet, QuickScanView

router = DefaultRouter()
router.register(r'tasks', DiscoveryTaskViewSet, basename='discovery-task')

urlpatterns = [
    url(r'^quick-scan/$', QuickScanView.as_view(), name='discovery-quick-scan'),
    url(r'^', include(router.urls)),
]
