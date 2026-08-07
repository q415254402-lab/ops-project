# -*- coding: utf-8 -*-
"""
自动发现 API

路由前缀：/api/v1/discovery/
    tasks/                    发现任务 CRUD
    tasks/{id}/run/           执行发现
    tasks/{id}/progress/      轮询进度（轻量）
    tasks/{id}/results/       发现结果（支持过滤 / 分页）
    tasks/{id}/import/        导入 CMDB
    quick-scan/               即时扫描（同步，最多 256 个地址）
"""
import logging
from concurrent.futures import ThreadPoolExecutor

from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.discovery.engine import expand_ip_ranges, probe_host
from apps.discovery.serializers import (
    DiscoveryTaskSerializer, ImportSerializer, QuickScanSerializer,
)
from apps.discovery.tasks.scan import import_discovered_devices, run_discovery_task
from apps.topology.models import DiscoveryTask

logger = logging.getLogger('esight.discovery')

# 即时扫描的地址上限，避免请求超时
QUICK_SCAN_LIMIT = 256


def dispatch_task(task_func, *args, **kwargs):
    """
    投递 Celery 任务；broker 不可用时退化为后台线程执行。

    本地开发常常没起 Redis/Celery，退化执行能保证功能可用。
    返回 'celery' 或 'thread'。

    注意：任务可能用 ``@shared_task(bind=True)`` 定义（首个参数 self），
    退化线程执行时不能直接 ``task_func(*args, **kwargs)``（self 会被位置参数占据），
    必须用 ``task_func.apply(args=args, kwargs=kwargs)`` 由 Celery 注入 self。
    """
    try:
        task_func.delay(*args, **kwargs)
        return 'celery'
    except Exception as exc:
        logger.warning('Celery 投递失败（%s），退化为本地线程执行', exc)
        import threading

        def _runner():
            try:
                task_func.apply(args=args, kwargs=kwargs)
            except Exception:
                logger.exception('本地线程执行任务失败')

        threading.Thread(target=_runner, daemon=True).start()
        return 'thread'


class DiscoveryTaskViewSet(viewsets.ModelViewSet):
    """发现任务管理"""
    queryset = DiscoveryTask.objects.prefetch_related('credentials').all()
    serializer_class = DiscoveryTaskSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['status']
    search_fields = ['name']
    ordering = ['-created_at']

    @action(detail=True, methods=['post'])
    def run(self, request, pk=None):
        """执行发现任务"""
        task = self.get_object()
        if task.status == 'running':
            return Response(
                {'detail': '任务正在执行中'}, status=status.HTTP_409_CONFLICT,
            )

        targets = expand_ip_ranges(task.ip_ranges)
        if not targets:
            return Response(
                {'detail': 'IP 范围为空或格式不合法'}, status=status.HTTP_400_BAD_REQUEST,
            )

        auto_import = bool(request.data.get('auto_import'))
        task.status = 'pending'
        task.error_message = ''
        task.result = {'progress': {'scanned': 0, 'total': len(targets), 'percent': 0}}
        task.save(update_fields=['status', 'error_message', 'result'])

        mode = dispatch_task(run_discovery_task, task.id, auto_import)
        return Response({
            'message': f'已提交发现任务，共 {len(targets)} 个目标',
            'total': len(targets),
            'mode': mode,
        })

    @action(detail=True, methods=['get'])
    def progress(self, request, pk=None):
        """轮询进度（不返回结果集，避免大 payload）"""
        task = self.get_object()
        result = task.result or {}
        return Response({
            'status': task.status,
            'progress': result.get('progress') or {},
            'summary': result.get('summary') or {},
            'discovered_count': task.discovered_count,
            'error_message': task.error_message,
        })

    @action(detail=True, methods=['get'])
    def results(self, request, pk=None):
        """
        发现结果列表

        query: ?snmp_only=1&device_type=switch&keyword=192.168&new_only=1
        """
        task = self.get_object()
        hosts = (task.result or {}).get('hosts', [])

        if request.query_params.get('snmp_only') in ('1', 'true'):
            hosts = [h for h in hosts if h.get('snmp_ok')]

        device_type = request.query_params.get('device_type')
        if device_type:
            hosts = [h for h in hosts if h.get('device_type') == device_type]

        keyword = (request.query_params.get('keyword') or '').strip().lower()
        if keyword:
            hosts = [
                h for h in hosts
                if keyword in (h.get('ip') or '').lower()
                or keyword in (h.get('hostname') or '').lower()
                or keyword in (h.get('vendor') or '').lower()
            ]

        # 标记是否已在 CMDB 中
        from apps.cmdb.models import Device
        existing = set(
            Device.objects.filter(
                ip_address__in=[h.get('ip') for h in hosts]
            ).values_list('ip_address', flat=True)
        )
        rows = []
        for host in hosts:
            row = {k: v for k, v in host.items() if k != 'interfaces'}
            row['interface_count'] = len(host.get('interfaces') or [])
            row['lldp_count'] = len(host.get('lldp_neighbors') or [])
            row['in_cmdb'] = host.get('ip') in existing
            rows.append(row)

        if request.query_params.get('new_only') in ('1', 'true'):
            rows = [r for r in rows if not r['in_cmdb']]

        return Response({
            'count': len(rows),
            'summary': (task.result or {}).get('summary') or {},
            'results': rows,
        })

    @action(detail=True, methods=['post'], url_path='import')
    def import_to_cmdb(self, request, pk=None):
        """把发现结果导入 CMDB（ips 为空表示全部）"""
        task = self.get_object()
        serializer = ImportSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        ips = serializer.validated_data.get('ips') or None

        if not (task.result or {}).get('hosts'):
            return Response(
                {'detail': '该任务暂无发现结果，请先执行扫描'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 导入通常很快，直接同步执行以便前端立刻拿到统计
        stats = import_discovered_devices(task.id, ips)
        return Response(stats)


class QuickScanView(APIView):
    """即时扫描（同步返回，适合小范围排查）"""

    def post(self, request):
        serializer = QuickScanSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        targets = expand_ip_ranges(data['ip_ranges'], max_hosts=QUICK_SCAN_LIMIT + 1)
        if not targets:
            return Response(
                {'detail': 'IP 范围为空或格式不合法'}, status=status.HTTP_400_BAD_REQUEST,
            )
        if len(targets) > QUICK_SCAN_LIMIT:
            return Response(
                {'detail': f'即时扫描最多支持 {QUICK_SCAN_LIMIT} 个地址，请改用发现任务'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        credentials = []
        if data.get('credentials'):
            from apps.cmdb.models import Credential
            credentials = list(Credential.objects.filter(id__in=data['credentials']))

        protocols = data.get('protocols') or ['icmp', 'snmp']
        timeout = data.get('timeout', 2)

        with ThreadPoolExecutor(max_workers=32) as pool:
            records = list(pool.map(
                lambda ip: probe_host(ip, credentials, protocols, timeout), targets,
            ))

        alive = [r for r in records if r.get('alive')]
        for row in alive:
            row.pop('interfaces', None)
            row.pop('lldp_neighbors', None)

        return Response({
            'total': len(targets),
            'alive': len(alive),
            'results': alive,
        })
