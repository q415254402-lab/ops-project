from rest_framework import viewsets
from apps.report.models import ReportTemplate, ReportInstance
from apps.report.serializers import ReportTemplateSerializer, ReportInstanceSerializer

class ReportTemplateViewSet(viewsets.ModelViewSet):
    queryset = ReportTemplate.objects.all()
    serializer_class = ReportTemplateSerializer
    filterset_fields = ['report_type', 'schedule_enabled']

class ReportInstanceViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = ReportInstance.objects.select_related('template').all()
    serializer_class = ReportInstanceSerializer
    filterset_fields = ['template', 'status']
    ordering = ['-generated_at']
