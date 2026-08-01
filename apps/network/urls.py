from django.conf.urls import url, include
from rest_framework.routers import DefaultRouter
from apps.network.api.network_views import SLAProbeViewSet, SLADataViewSet, NetflowRecordViewSet

router = DefaultRouter()
router.register(r'sla/probes', SLAProbeViewSet)
router.register(r'sla/data', SLADataViewSet)
router.register(r'netflow', NetflowRecordViewSet)

urlpatterns = [url(r'^', include(router.urls))]
