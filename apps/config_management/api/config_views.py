from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from apps.config_management.models import ConfigBackup, ConfigTemplate, ComplianceRule, ComplianceCheckResult, BatchJob
from apps.config_management.serializers import (
    ConfigBackupSerializer, ConfigTemplateSerializer,
    ComplianceRuleSerializer, ComplianceCheckResultSerializer, BatchJobSerializer,
)

class ConfigBackupViewSet(viewsets.ModelViewSet):
    queryset = ConfigBackup.objects.select_related('device').all()
    serializer_class = ConfigBackupSerializer
    filterset_fields = ['device', 'config_type', 'is_changed']
    ordering = ['-created_at']

    @action(detail=True, methods=['get'])
    def diff(self, request, pk=None):
        backup = self.get_object()
        return Response({'diff': backup.diff_content, 'checksum': backup.checksum})

class ConfigTemplateViewSet(viewsets.ModelViewSet):
    queryset = ConfigTemplate.objects.all()
    serializer_class = ConfigTemplateSerializer
    filterset_fields = ['device_type']

class ComplianceRuleViewSet(viewsets.ModelViewSet):
    queryset = ComplianceRule.objects.all()
    serializer_class = ComplianceRuleSerializer
    filterset_fields = ['device_type', 'rule_type', 'enabled']

class ComplianceCheckResultViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = ComplianceCheckResult.objects.select_related('rule', 'device').all()
    serializer_class = ComplianceCheckResultSerializer
    filterset_fields = ['device', 'passed']

class BatchJobViewSet(viewsets.ModelViewSet):
    queryset = BatchJob.objects.all()
    serializer_class = BatchJobSerializer
    filterset_fields = ['status']
