from rest_framework import serializers
from apps.performance.models import MetricDefinition, CollectTask, MetricThreshold, MetricData, InterfaceTraffic

class MetricDefinitionSerializer(serializers.ModelSerializer):
    device_type_name = serializers.CharField(source='device_type.name', read_only=True, default='')
    class Meta:
        model = MetricDefinition
        fields = '__all__'

class CollectTaskSerializer(serializers.ModelSerializer):
    device_count = serializers.SerializerMethodField()
    metric_count = serializers.SerializerMethodField()
    class Meta:
        model = CollectTask
        fields = '__all__'
    def get_device_count(self, obj):
        return obj.devices.count()
    def get_metric_count(self, obj):
        return obj.metrics.count()

class MetricThresholdSerializer(serializers.ModelSerializer):
    metric_name = serializers.CharField(source='metric.name', read_only=True, default='')
    class Meta:
        model = MetricThreshold
        fields = '__all__'

class MetricDataSerializer(serializers.ModelSerializer):
    metric_name = serializers.CharField(source='metric.name', read_only=True, default='')
    metric_unit = serializers.CharField(source='metric.unit', read_only=True, default='')
    class Meta:
        model = MetricData
        fields = '__all__'
