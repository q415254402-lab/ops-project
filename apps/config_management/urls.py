from django.urls import re_path, include
from rest_framework.routers import DefaultRouter
from apps.config_management.api.config_views import (
    ConfigBackupViewSet, ConfigTemplateViewSet,
    ComplianceRuleViewSet, ComplianceCheckResultViewSet, BatchJobViewSet,
)

router = DefaultRouter()
router.register(r'backups', ConfigBackupViewSet)
router.register(r'templates', ConfigTemplateViewSet)
router.register(r'compliance/rules', ComplianceRuleViewSet)
router.register(r'compliance/results', ComplianceCheckResultViewSet)
router.register(r'batch-jobs', BatchJobViewSet)

urlpatterns = [re_path(r'^', include(router.urls))]
