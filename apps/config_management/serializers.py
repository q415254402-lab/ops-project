from rest_framework import serializers
from apps.config_management.models import ConfigBackup, ConfigTemplate, ComplianceRule, ComplianceCheckResult, BatchJob

class ConfigBackupSerializer(serializers.ModelSerializer):
    device_name = serializers.CharField(source='device.name', read_only=True, default='')
    class Meta:
        model = ConfigBackup
        fields = '__all__'

class ConfigTemplateSerializer(serializers.ModelSerializer):
    device_type_name = serializers.CharField(source='device_type.name', read_only=True, default='')
    class Meta:
        model = ConfigTemplate
        fields = '__all__'

class ComplianceRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = ComplianceRule
        fields = '__all__'

class ComplianceCheckResultSerializer(serializers.ModelSerializer):
    rule_name = serializers.CharField(source='rule.name', read_only=True, default='')
    device_name = serializers.CharField(source='device.name', read_only=True, default='')
    class Meta:
        model = ComplianceCheckResult
        fields = '__all__'

class BatchJobSerializer(serializers.ModelSerializer):
    class Meta:
        model = BatchJob
        fields = '__all__'
