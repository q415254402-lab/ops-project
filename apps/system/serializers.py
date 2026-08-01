from rest_framework import serializers
from apps.system.models import OperationLog, SystemParameter, DataDict

class OperationLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = OperationLog
        fields = '__all__'

class SystemParameterSerializer(serializers.ModelSerializer):
    class Meta:
        model = SystemParameter
        fields = '__all__'

class DataDictSerializer(serializers.ModelSerializer):
    class Meta:
        model = DataDict
        fields = '__all__'
