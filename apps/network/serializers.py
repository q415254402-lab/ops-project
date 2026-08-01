from rest_framework import serializers
from apps.network.models import SLAProbe, SLAData, NetflowRecord

class SLAProbeSerializer(serializers.ModelSerializer):
    source_device_name = serializers.CharField(source='source_device.name', read_only=True, default='')
    class Meta:
        model = SLAProbe
        fields = '__all__'

class SLADataSerializer(serializers.ModelSerializer):
    class Meta:
        model = SLAData
        fields = '__all__'

class NetflowRecordSerializer(serializers.ModelSerializer):
    class Meta:
        model = NetflowRecord
        fields = '__all__'
