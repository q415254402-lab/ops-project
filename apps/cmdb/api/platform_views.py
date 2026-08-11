# -*- coding: utf-8 -*-
"""
平台管控薄代理 API —— eSight 前端调用，转发到 OpsAny 管控平台(control)。

原则：eSight 不维护第二套设备/厂商/类型数据，全部只读平台。
前端 baseURL=/t/esight/api/v1，本模块挂载于 /api/v1/cmdb/platform/。

CSRF 处理（重要，2026-08-11 实测修复）：
- DRF 的 SessionAuthentication.enforce_csrf() 在视图 dispatch 内部强制 CSRF 检查，
  它不认 Django 的 csrf_exempt 标志（之前 method_decorator(csrf_exempt) 无效，POST 仍 403）。
- 正确做法：子类化 SessionAuthentication 并禁用 enforce_csrf，
  薄代理视图用它（平台走 bk_token 会话鉴权，eSight 的 CSRF 无意义）。
"""
from rest_framework.authentication import SessionAuthentication
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.cmdb.services import platform_proxy


class CSRFExemptSessionAuthentication(SessionAuthentication):
    """禁用 CSRF 的 SessionAuthentication（薄代理专用）"""

    def enforce_csrf(self, request):
        return  # 跳过 DRF 的 CSRF 强制检查


class _BaseProxy(APIView):
    """薄代理基类：捕获平台错误，统一返回 {code, message, data}"""
    authentication_classes = [CSRFExemptSessionAuthentication]

    def _ok(self, data):
        return Response({'code': 200, 'message': 'success', 'data': data})

    def _err(self, exc):
        return Response(
            {'code': 500, 'message': str(exc), 'data': None},
            status=status.HTTP_502_BAD_GATEWAY,
        )


class NetworkEquipmentListProxy(_BaseProxy):
    """设备列表（平台已纳管设备）"""

    def get(self, request):
        try:
            data = platform_proxy.get_network_equipments(request=request)
            return self._ok(data)
        except Exception as exc:  # noqa: BLE001
            return self._err(exc)


class NetworkEquipmentSaveProxy(_BaseProxy):
    """添加/编辑设备（POST/PUT network-equipment/）"""

    def post(self, request):
        try:
            data = platform_proxy.add_network_equipment(request.data, request=request)
            return self._ok(data)
        except Exception as exc:  # noqa: BLE001
            return self._err(exc)

    def put(self, request):
        try:
            data = platform_proxy.edit_network_equipment(request.data, request=request)
            return self._ok(data)
        except Exception as exc:  # noqa: BLE001
            return self._err(exc)


class NetworkEquipmentDeleteProxy(_BaseProxy):
    """删除设备（DELETE network-equipment/）"""

    def delete(self, request):
        try:
            data = platform_proxy.delete_network_equipment(request.data, request=request)
            return self._ok(data)
        except Exception as exc:  # noqa: BLE001
            return self._err(exc)


class NetworkEquipmentFlushProxy(_BaseProxy):
    """刷新/同步设备"""

    def get(self, request):
        try:
            data = platform_proxy.flush_network_equipment(request=request, **request.query_params.dict())
            return self._ok(data)
        except Exception as exc:  # noqa: BLE001
            return self._err(exc)


class NetworkFromCMDBProxy(_BaseProxy):
    """从资源平台(CMDB)拉取网络设备（"从资源平台添加"弹窗数据）"""

    def get(self, request):
        try:
            data = platform_proxy.get_network_from_cmdb(request=request)
            return self._ok(data)
        except Exception as exc:  # noqa: BLE001
            return self._err(exc)


class NetworkEquipmentTestProxy(_BaseProxy):
    """连接测试（SNMP/SSH/Telnet 分协议）"""

    def post(self, request):
        try:
            data = platform_proxy.test_network_equipment(request.data, request=request)
            return self._ok(data)
        except Exception as exc:  # noqa: BLE001
            return self._err(exc)


class NetworkEquipmentPingProxy(_BaseProxy):
    """Ping 测试"""

    def post(self, request):
        try:
            data = platform_proxy.ping_network_equipment(request.data, request=request)
            return self._ok(data)
        except Exception as exc:  # noqa: BLE001
            return self._err(exc)


class EquipmentTypeProxy(_BaseProxy):
    """厂商品牌 + 设备类型"""

    def get(self, request):
        try:
            data = platform_proxy.get_equipment_type_v2(request=request)
            return self._ok(data)
        except Exception as exc:  # noqa: BLE001
            return self._err(exc)


class NetworkTypeProxy(_BaseProxy):
    """设备类型列表"""

    def get(self, request):
        try:
            data = platform_proxy.get_network_types(request=request)
            return self._ok(data)
        except Exception as exc:  # noqa: BLE001
            return self._err(exc)


class NetworkGroupProxy(_BaseProxy):
    """设备分组"""

    def get(self, request):
        try:
            data = platform_proxy.get_network_groups(request=request)
            return self._ok(data)
        except Exception as exc:  # noqa: BLE001
            return self._err(exc)


class ZcModelProxy(_BaseProxy):
    """资产模型"""

    def get(self, request):
        try:
            data = platform_proxy.get_zc_models(request=request)
            return self._ok(data)
        except Exception as exc:  # noqa: BLE001
            return self._err(exc)


class ControllerProxy(_BaseProxy):
    """控制器列表（连接测试/保存设备必带 controller_id）"""

    def get(self, request):
        try:
            data = platform_proxy.get_controllers(request=request)
            return self._ok(data)
        except Exception as exc:  # noqa: BLE001
            return self._err(exc)
