from rest_framework import viewsets
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from apps.system.models import OperationLog, SystemParameter, DataDict
from apps.system.serializers import OperationLogSerializer, SystemParameterSerializer, DataDictSerializer


class OperationLogViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = OperationLog.objects.all()
    serializer_class = OperationLogSerializer
    filterset_fields = ['user', 'action', 'resource_type']
    search_fields = ['user', 'resource_name', 'detail']
    ordering = ['-created_at']


class SystemParameterViewSet(viewsets.ModelViewSet):
    queryset = SystemParameter.objects.all()
    serializer_class = SystemParameterSerializer
    filterset_fields = ['category']


class DataDictViewSet(viewsets.ModelViewSet):
    queryset = DataDict.objects.all()
    serializer_class = DataDictSerializer
    filterset_fields = ['type_code', 'enabled']


class CurrentUserView(APIView):
    """当前登录用户信息（用户目录由 OpsAny 平台统一管理）"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({
            'username': getattr(user, 'username', ''),
            'name': getattr(user, 'name', '') or getattr(user, 'nickname', '') or getattr(user, 'username', ''),
            'email': getattr(user, 'email', ''),
            'is_superuser': getattr(user, 'is_superuser', False),
            'platform_managed': True,
        })


class UserListView(APIView):
    """用户列表（来自 OpsAny 平台会话；完整目录请前往平台管理）"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        last_login = getattr(user, 'last_login', None)
        me = {
            'username': getattr(user, 'username', ''),
            'name': getattr(user, 'name', '') or getattr(user, 'nickname', '') or getattr(user, 'username', ''),
            'email': getattr(user, 'email', ''),
            'role': '超级管理员' if getattr(user, 'is_superuser', False) else '运维人员',
            'status': 'active',
            'last_login': last_login.isoformat() if last_login else '',
            'platform_managed': True,
        }
        return Response([me])
