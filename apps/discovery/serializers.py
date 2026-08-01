# -*- coding: utf-8 -*-
"""自动发现序列化器"""
from rest_framework import serializers

from apps.topology.models import DiscoveryTask


class DiscoveryTaskSerializer(serializers.ModelSerializer):
    """发现任务（列表 / 详情通用，结果集不整包返回）"""
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    credential_names = serializers.SerializerMethodField()
    progress = serializers.SerializerMethodField()
    summary = serializers.SerializerMethodField()

    class Meta:
        model = DiscoveryTask
        fields = [
            'id', 'name', 'ip_ranges', 'protocols', 'credentials', 'credential_names',
            'status', 'status_display', 'discovered_count', 'error_message',
            'scheduled_at', 'started_at', 'completed_at', 'created_at',
            'progress', 'summary',
        ]
        read_only_fields = [
            'status', 'discovered_count', 'error_message',
            'started_at', 'completed_at', 'created_at',
        ]

    def get_credential_names(self, obj):
        return [c.name for c in obj.credentials.all()]

    def get_progress(self, obj):
        return (obj.result or {}).get('progress') or {}

    def get_summary(self, obj):
        return (obj.result or {}).get('summary') or {}


class QuickScanSerializer(serializers.Serializer):
    """即时扫描入参"""
    ip_ranges = serializers.ListField(
        child=serializers.CharField(), allow_empty=False,
    )
    protocols = serializers.ListField(
        child=serializers.ChoiceField(choices=['icmp', 'snmp', 'lldp']),
        required=False, default=['icmp', 'snmp'],
    )
    credentials = serializers.ListField(
        child=serializers.IntegerField(), required=False, default=list,
    )
    timeout = serializers.IntegerField(required=False, default=2, min_value=1, max_value=10)


class ImportSerializer(serializers.Serializer):
    """导入 CMDB 入参"""
    ips = serializers.ListField(
        child=serializers.CharField(), required=False, allow_empty=True, default=list,
    )
