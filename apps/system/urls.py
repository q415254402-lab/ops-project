from django.urls import re_path, include
from rest_framework.routers import DefaultRouter
from apps.system.api.system_views import (
    OperationLogViewSet,
    SystemParameterViewSet,
    DataDictViewSet,
    UserListView,
    CurrentUserView,
)

router = DefaultRouter()
router.register(r'audit-logs', OperationLogViewSet)
router.register(r'params', SystemParameterViewSet)
router.register(r'dicts', DataDictViewSet)

urlpatterns = [
    re_path(r'^current-user/$', CurrentUserView.as_view()),
    re_path(r'^users/$', UserListView.as_view()),
    re_path(r'^', include(router.urls)),
]
