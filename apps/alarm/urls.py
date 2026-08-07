"""
告警 URL 路由
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .api.alarm_views import AlarmViewSet, AlarmDefinitionViewSet

router = DefaultRouter()
# 注意：AlarmViewSet 空前缀注册，其 detail 路由 ^(?P<pk>[^/.]+)/$ 会吞掉其后注册的
# definitions 等路径（pk='definitions' → BigInteger 转换 500）。必须先把固定前缀路由注册在前。
router.register(r'definitions', AlarmDefinitionViewSet)
router.register(r'', AlarmViewSet, basename='alarm')

urlpatterns = [
    path('', include(router.urls)),
]
