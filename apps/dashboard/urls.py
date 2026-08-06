from django.urls import re_path
from apps.dashboard.api.dashboard_views import DashboardOverviewView, HealthCheckView

urlpatterns = [
    re_path(r'^overview/$', DashboardOverviewView.as_view()),
    re_path(r'^health/$', HealthCheckView.as_view()),
]
