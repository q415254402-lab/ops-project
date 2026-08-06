# -*- coding: utf-8 -*-
from django.urls import re_path, include
from rest_framework.routers import DefaultRouter

from apps.discovery.api.discovery_views import DiscoveryTaskViewSet, QuickScanView

router = DefaultRouter()
router.register(r'tasks', DiscoveryTaskViewSet, basename='discovery-task')

urlpatterns = [
    re_path(r'^quick-scan/$', QuickScanView.as_view(), name='discovery-quick-scan'),
    re_path(r'^', include(router.urls)),
]
