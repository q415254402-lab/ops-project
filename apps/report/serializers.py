from rest_framework import serializers
from apps.report.models import ReportTemplate, ReportInstance

class ReportTemplateSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReportTemplate
        fields = '__all__'

class ReportInstanceSerializer(serializers.ModelSerializer):
    template_name = serializers.CharField(source='template.name', read_only=True, default='')
    class Meta:
        model = ReportInstance
        fields = '__all__'
