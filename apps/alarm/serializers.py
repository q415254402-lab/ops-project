"""
告警序列化器
"""
from rest_framework import serializers
from .models import Alarm, AlarmDefinition, AlarmHistory


class AlarmDefinitionSerializer(serializers.ModelSerializer):
    severity_display = serializers.CharField(source='get_severity_display', read_only=True)
    source_display = serializers.CharField(source='get_source_display', read_only=True)

    class Meta:
        model = AlarmDefinition
        fields = '__all__'


class AlarmSerializer(serializers.ModelSerializer):
    device_name = serializers.CharField(source='device.name', read_only=True, default='')
    device_ip = serializers.CharField(source='device.ip_address', read_only=True, default='')
    severity_display = serializers.CharField(source='get_severity_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    alarm_name = serializers.CharField(source='alarm_definition.name', read_only=True, default='')

    class Meta:
        model = Alarm
        fields = '__all__'


class AlarmListSerializer(serializers.ModelSerializer):
    device_name = serializers.CharField(source='device.name', read_only=True, default='')
    device_ip = serializers.CharField(source='device.ip_address', read_only=True, default='')
    severity_display = serializers.CharField(source='get_severity_display', read_only=True)

    class Meta:
        model = Alarm
        fields = [
            'id', 'title', 'severity', 'severity_display', 'status',
            'device', 'device_name', 'device_ip',
            'occurrence_count', 'first_occurred_at', 'last_occurred_at',
        ]


class AlarmHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = AlarmHistory
        fields = '__all__'
