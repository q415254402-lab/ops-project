"""
告警 URL 路由
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .api.alarm_views import AlarmViewSet, AlarmDefinitionViewSet

router = DefaultRouter()
router.register(r'', AlarmViewSet, basename='alarm')
router.register(r'definitions', AlarmDefinitionViewSet)

urlpatterns = [
    path('', include(router.urls)),
]
