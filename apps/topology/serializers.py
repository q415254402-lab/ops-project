from rest_framework import serializers
from apps.topology.models import TopologyMap, TopologyNode, TopologyLink, DiscoveryTask

class TopologyNodeSerializer(serializers.ModelSerializer):
    class Meta:
        model = TopologyNode
        fields = '__all__'

class TopologyLinkSerializer(serializers.ModelSerializer):
    class Meta:
        model = TopologyLink
        fields = '__all__'

class TopologyMapSerializer(serializers.ModelSerializer):
    node_count = serializers.SerializerMethodField()
    link_count = serializers.SerializerMethodField()
    class Meta:
        model = TopologyMap
        fields = '__all__'
    def get_node_count(self, obj):
        return obj.nodes.count()
    def get_link_count(self, obj):
        return obj.links.count()

class DiscoveryTaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = DiscoveryTask
        fields = '__all__'
