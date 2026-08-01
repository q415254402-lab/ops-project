from django.conf.urls import url, include
from rest_framework.routers import DefaultRouter
from apps.report.api.report_views import ReportTemplateViewSet, ReportInstanceViewSet

router = DefaultRouter()
router.register(r'templates', ReportTemplateViewSet)
router.register(r'instances', ReportInstanceViewSet)

urlpatterns = [url(r'^', include(router.urls))]
