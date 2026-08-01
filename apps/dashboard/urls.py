from django.conf.urls import url
from apps.dashboard.api.dashboard_views import DashboardOverviewView, HealthCheckView

urlpatterns = [
    url(r'^overview/$', DashboardOverviewView.as_view()),
    url(r'^health/$', HealthCheckView.as_view()),
]
