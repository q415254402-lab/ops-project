"""
CMDB 序列化器
"""
from rest_framework import serializers
from .models import (
    Manufacturer, Credential, DeviceType, DeviceModel,
    Device, Interface, Vlan, IPAddress, Server,
    Room, Cabinet,
)


class ManufacturerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Manufacturer
        fields = '__all__'


class DeviceTypeSerializer(serializers.ModelSerializer):
    children = serializers.SerializerMethodField()

    class Meta:
        model = DeviceType
        fields = '__all__'

    def get_children(self, obj):
        children = obj.children.all()
        return DeviceTypeSerializer(children, many=True).data


class DeviceModelSerializer(serializers.ModelSerializer):
    manufacturer_name = serializers.CharField(source='manufacturer.name', read_only=True)
    device_type_name = serializers.CharField(source='device_type.name', read_only=True)

    class Meta:
        model = DeviceModel
        fields = '__all__'


class CredentialSerializer(serializers.ModelSerializer):
    """凭据序列化器（密码脱敏）"""
    password = serializers.CharField(write_only=True, required=False, allow_blank=True)

    class Meta:
        model = Credential
        fields = '__all__'
        extra_kwargs = {'ssh_key': {'write_only': True}}


class InterfaceSerializer(serializers.ModelSerializer):
    status_display = serializers.CharField(source='get_status_display', read_only=True)

    class Meta:
        model = Interface
        fields = '__all__'


class DeviceListSerializer(serializers.ModelSerializer):
    """设备列表序列化器"""
    device_type_name = serializers.CharField(source='device_type.name', read_only=True)
    manufacturer_name = serializers.CharField(source='manufacturer.name', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    alarm_count = serializers.SerializerMethodField()

    class Meta:
        model = Device
        fields = [
            'id', 'name', 'hostname', 'ip_address', 'mac_address',
            'device_type', 'device_type_name', 'manufacturer', 'manufacturer_name',
            'status', 'status_display', 'manage_type',
            'room', 'cabinet', 'tags',
            'last_sync_at', 'last_seen_at', 'created_at',
            'alarm_count',
        ]

    def get_alarm_count(self, obj):
        return obj.alarms.filter(status='active').count()


class DeviceDetailSerializer(serializers.ModelSerializer):
    """设备详情序列化器"""
    device_type_name = serializers.CharField(source='device_type.name', read_only=True)
    manufacturer_name = serializers.CharField(source='manufacturer.name', read_only=True)
    model_name = serializers.CharField(source='device_model.name', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    interfaces = InterfaceSerializer(many=True, read_only=True)
    alarm_count = serializers.SerializerMethodField()
    server_detail = serializers.SerializerMethodField()

    class Meta:
        model = Device
        fields = '__all__'

    def get_alarm_count(self, obj):
        return obj.alarms.filter(status='active').count()

    def get_server_detail(self, obj):
        if hasattr(obj, 'server_detail'):
            from .models import Server
            return {
                'cpu_model': obj.server_detail.cpu_model,
                'cpu_cores': obj.server_detail.cpu_cores,
                'memory_total_gb': obj.server_detail.memory_total_gb,
                'disk_total_gb': obj.server_detail.disk_total_gb,
                'os_name': obj.server_detail.os_name,
            }
        return None


class DeviceCreateUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = [
            'name', 'hostname', 'ip_address', 'mac_address',
            'device_type', 'device_model', 'manufacturer',
            'serial_number', 'firmware_version', 'os_version',
            'status', 'manage_type', 'room', 'cabinet', 'cabinet_position',
            'credential', 'tags', 'description',
        ]


class VlanSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vlan
        fields = '__all__'


class IPAddressSerializer(serializers.ModelSerializer):
    device_name = serializers.CharField(source='device.name', read_only=True, default='')

    class Meta:
        model = IPAddress
        fields = '__all__'


class RoomSerializer(serializers.ModelSerializer):
    device_count = serializers.SerializerMethodField()

    class Meta:
        model = Room
        fields = '__all__'

    def get_device_count(self, obj):
        return obj.devices.count()


class CabinetSerializer(serializers.ModelSerializer):
    room_name = serializers.CharField(source='room.name', read_only=True)
    usage_percent = serializers.SerializerMethodField()

    class Meta:
        model = Cabinet
        fields = '__all__'

    def get_usage_percent(self, obj):
        return round(obj.used_u / obj.total_u * 100, 1) if obj.total_u > 0 else 0
