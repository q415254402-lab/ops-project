from rest_framework import viewsets
from apps.network.models import SLAProbe, SLAData, NetflowRecord
from apps.network.serializers import SLAProbeSerializer, SLADataSerializer, NetflowRecordSerializer

class SLAProbeViewSet(viewsets.ModelViewSet):
    queryset = SLAProbe.objects.select_related('source_device').all()
    serializer_class = SLAProbeSerializer
    filterset_fields = ['probe_type', 'enabled', 'source_device']

class SLADataViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = SLAData.objects.all()
    serializer_class = SLADataSerializer
    filterset_fields = ['probe']

class NetflowRecordViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = NetflowRecord.objects.all()
    serializer_class = NetflowRecordSerializer
    filterset_fields = ['source_ip', 'dest_ip', 'protocol']
