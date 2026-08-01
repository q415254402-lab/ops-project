from django.conf.urls import url, include
from rest_framework.routers import DefaultRouter
from apps.system.api.system_views import (
    OperationLogViewSet,
    SystemParameterViewSet,
    DataDictViewSet,
    UserListView,
)

router = DefaultRouter()
router.register(r'audit-logs', OperationLogViewSet)
router.register(r'params', SystemParameterViewSet)
router.register(r'dicts', DataDictViewSet)

urlpatterns = [
    url(r'^users/$', UserListView.as_view()),
    url(r'^', include(router.urls)),
]
