# -*- coding: utf-8 -*-
"""
eSight 网络设备 view（完全复刻 OpsAny control 网络设备模块，本地落库）
- 不再代理平台，所有数据落到 eSight 数据库
- 路径前缀 /cmdb/network/...
"""
import hashlib
import json
import logging
from base64 import urlsafe_b64encode, urlsafe_b64decode
from django.db import transaction
from django.db.models import Q
from django.http import JsonResponse
from rest_framework.views import APIView
from rest_framework.authentication import SessionAuthentication

logger = logging.getLogger('app')


class PasswordEncryption:
    """完全复刻 control/utils/encryption.py + opsany-paas-proxy proxy/utils/encryption.py
    AES-ECB + MD5(key) + PKCS#5 padding + urlsafe_b64（去 =）
    key 必须与 control SECRET_KEY / agent CONTROL_SECRET_KEY 一致（7ce1271a-...），
    否则 eSight 存的密文 agent 解不开、agent 同步来的密文 eSight 也解不开。
    """

    CONTROL_SECRET_KEY = '7ce1271a-571b-4afd-b8f3-9f1bde4727d3'

    @staticmethod
    def _pad(text, blocksize=16):
        pad = blocksize - len(text) % blocksize
        return (text + pad * chr(pad)).encode('utf-8')

    @staticmethod
    def _unpad(text):
        return text[:-ord(text[-1:])]

    def encrypt(self, plaintext, key='', base64=True):
        try:
            from Crypto.Cipher import AES
        except ImportError:
            from Cryptodome.Cipher import AES
        if not key:
            key = self.CONTROL_SECRET_KEY
        key = hashlib.md5(key.encode('utf-8')).digest()
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(self._pad(str(plaintext)))
        if base64:
            ciphertext = urlsafe_b64encode(ciphertext).decode('utf-8').rstrip('=')
        return ciphertext

    def decrypt(self, ciphertext, key='', base64=True):
        try:
            from Crypto.Cipher import AES
        except ImportError:
            from Cryptodome.Cipher import AES
        if not key:
            key = self.CONTROL_SECRET_KEY
        if base64:
            ciphertext = urlsafe_b64decode(str(ciphertext) + '=' * (4 - len(str(ciphertext)) % 4))
        key = hashlib.md5(key.encode('utf-8')).digest()
        cipher = AES.new(key, AES.MODE_ECB)
        return self._unpad(cipher.decrypt(ciphertext).decode('utf-8'))


class CSRFExemptSessionAuthentication(SessionAuthentication):
    def enforce_csrf(self, request):
        return  # 禁用 DRF 强制 CSRF


def ok(data=None, msg='信息获取成功'):
    # 注意：空列表 [] 是 falsy，不能用 `data or {}`，否则空数组会被转成 {} 导致前端分组树/列表崩
    if data is None:
        data = {}
    return JsonResponse({'code': 200, 'successcode': 20005, 'message': msg, 'data': data})


def err(msg, code=50000, http=200):
    return JsonResponse({'code': code, 'message': msg, 'errcode': code, 'data': None}, status=http)


# ────────────────── 设备类型 ──────────────────
class NetworkTypeView(APIView):
    authentication_classes = [CSRFExemptSessionAuthentication]

    # 种子数据：控制平台内置的 3 大设备类型（id 必须与 control 一致）
    SEED_TYPES = [
        {'id': 1, 'code': 'ROUTER', 'name': '路由器', 'built_in': True},
        {'id': 2, 'code': 'SWITCH', 'name': '交换机', 'built_in': True},
        {'id': 3, 'code': 'FIREWALL', 'name': '防火墙', 'built_in': True},
    ]

    def get(self, request):
        from apps.cmdb.models.control_models import EquipmentTypeCMDBModel
        if not EquipmentTypeCMDBModel.objects.exists():
            for t in self.SEED_TYPES:
                EquipmentTypeCMDBModel.objects.create(**t)
        items = [t.to_dict() for t in EquipmentTypeCMDBModel.objects.all().order_by('id')]
        return ok(items, '信息获取成功')


class NetworkEquipmentTypeV2View(APIView):
    """厂商品牌 + 设备型号（v2 静态配置，对齐 control constants.device_type_list_v2）"""
    authentication_classes = [CSRFExemptSessionAuthentication]

    BRANDS = [
        {'brand_name': 'Huawei', 'brand_code': 'huawei',
         'device_type_list': [
             {'device_type': 'huawei', 'support': ['SSH', 'Telnet']},
             {'device_type': 'huawei_smartax', 'support': ['SSH']},
             {'device_type': 'huawei_olt', 'support': ['SSH', 'Telnet']},
             {'device_type': 'huawei_vrpv8', 'support': ['SSH']},
         ]},
        {'brand_name': 'HP/H3C', 'brand_code': 'hp',
         'device_type_list': [
             {'device_type': 'hp_comware', 'support': ['SSH', 'Telnet']},
             {'device_type': 'hp_procurve', 'support': ['SSH', 'Telnet']},
         ]},
        {'brand_name': 'DELL', 'brand_code': 'dell',
         'device_type_list': [
             {'device_type': 'dell_dnos9', 'support': ['SSH']},
             {'device_type': 'dell_force10', 'support': ['SSH']},
             {'device_type': 'dell_os6', 'support': ['SSH']},
             {'device_type': 'dell_os9', 'support': ['SSH']},
             {'device_type': 'dell_os10', 'support': ['SSH']},
             {'device_type': 'dell_sonic', 'support': ['SSH']},
             {'device_type': 'dell_powerconnect', 'support': ['SSH', 'Telnet']},
             {'device_type': 'dell_isilon', 'support': ['SSH']},
         ]},
        {'brand_name': 'Cisco', 'brand_code': 'cisco',
         'device_type_list': [
             {'device_type': 'cisco_asa', 'support': ['SSH']},
             {'device_type': 'cisco_ftd', 'support': ['SSH']},
             {'device_type': 'cisco_ios', 'support': ['SSH', 'Telnet']},
             {'device_type': 'cisco_nxos', 'support': ['SSH']},
             {'device_type': 'cisco_s300', 'support': ['SSH', 'Telnet']},
             {'device_type': 'cisco_tp', 'support': ['SSH']},
             {'device_type': 'cisco_viptela', 'support': ['SSH']},
             {'device_type': 'cisco_wlc', 'support': ['SSH']},
             {'device_type': 'cisco_xe', 'support': ['SSH']},
             {'device_type': 'cisco_xr', 'support': ['SSH', 'Telnet']},
         ]},
        {'brand_name': 'TpLink', 'brand_code': 'tplink',
         'device_type_list': [
             {'device_type': 'tplink_jetstream', 'support': ['SSH', 'Telnet']},
         ]},
        {'brand_name': '博科', 'brand_code': 'brocade',
         'device_type_list': [
             {'device_type': 'brocade_fos', 'support': ['SSH']},
             {'device_type': 'brocade_fastiron', 'support': ['SSH']},
             {'device_type': 'brocade_netiron', 'support': ['SSH', 'Telnet']},
             {'device_type': 'brocade_nos', 'support': ['SSH']},
             {'device_type': 'brocade_vdx', 'support': ['SSH']},
             {'device_type': 'brocade_vyos', 'support': ['SSH']},
         ]},
        {'brand_name': '锐捷', 'brand_code': 'ruijie',
         'device_type_list': [
             {'device_type': 'ruijie_os', 'support': ['SSH', 'Telnet']},
         ]},
        {'brand_name': '极进', 'brand_code': 'extreme',
         'device_type_list': [
             {'device_type': 'extreme', 'support': ['SSH', 'Telnet']},
             {'device_type': 'extreme_ers', 'support': ['SSH']},
             {'device_type': 'extreme_exos', 'support': ['SSH', 'Telnet']},
             {'device_type': 'extreme_netiron', 'support': ['SSH', 'Telnet']},
             {'device_type': 'extreme_nos', 'support': ['SSH']},
             {'device_type': 'extreme_slx', 'support': ['SSH']},
             {'device_type': 'extreme_tierra', 'support': ['SSH']},
             {'device_type': 'extreme_vdx', 'support': ['SSH']},
             {'device_type': 'extreme_vsp', 'support': ['SSH']},
             {'device_type': 'extreme_wing', 'support': ['SSH']},
         ]},
        {'brand_name': 'Aruba', 'brand_code': 'aruba',
         'device_type_list': [
             {'device_type': 'aruba_os', 'support': ['SSH']},
             {'device_type': 'aruba_osswitch', 'support': ['SSH']},
             {'device_type': 'aruba_procurve', 'support': ['SSH', 'Telnet']},
         ]},
        {'brand_name': 'Juniper', 'brand_code': 'juniper',
         'device_type_list': [
             {'device_type': 'juniper', 'support': ['SSH']},
             {'device_type': 'juniper_junos', 'support': ['SSH', 'Telnet']},
             {'device_type': 'juniper_screenos', 'support': ['SSH']},
         ]},
        {'brand_name': '优倍快', 'brand_code': 'ubiquiti',
         'device_type_list': [
             {'device_type': 'ubiquiti_edge', 'support': ['SSH']},
             {'device_type': 'ubiquiti_edgerouter', 'support': ['SSH']},
         ]},
        {'brand_name': '迈普', 'brand_code': 'maipu',
         'device_type_list': [
             {'device_type': 'maipu', 'support': ['SSH', 'Telnet']},
         ]},
        {'brand_name': '华三', 'brand_code': 'h3c',
         'device_type_list': [
             {'device_type': 'h3c', 'support': ['SSH', 'Telnet']},
         ]},
    ]

    def get(self, request):
        return ok(self.BRANDS, '信息获取成功')


# ────────────────── 分组 ──────────────────
class NetworkGroupView(APIView):
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        from apps.cmdb.models.control_models import NetworkGroupModel
        # 对齐 control _get_network_group：顶层分组树（parent=None），默认分组排最前
        groups = list(NetworkGroupModel.objects.filter(parent__isnull=True).order_by('create_time'))
        groups.sort(key=lambda g: 0 if g.name == '默认分组' else 1)
        items = [g.to_parent_auth_dict_v2() for g in groups]
        return ok(items, '信息获取成功')

    def post(self, request):
        from apps.cmdb.models.control_models import NetworkGroupModel
        data = json.loads(request.body or b'{}')
        name = data.get('name')
        parent_id = data.get('parent_id')
        if not name:
            return err('分组名称不能为空')
        if '/' in name:
            return err('分组名不支持 /')
        if NetworkGroupModel.objects.filter(name=name).exists():
            return err('分组名已存在')
        g = NetworkGroupModel.objects.create(
            name=name,
            parent_id=parent_id if parent_id else None,
            creator=data.get('creator', 'admin'),
            description=data.get('description', ''),
        )
        return ok(g.to_dict(), '信息创建成功')

    def put(self, request):
        from apps.cmdb.models.control_models import NetworkGroupModel
        data = json.loads(request.body or b'{}')
        gid = data.get('id')
        if not gid:
            return err('id 不能为空')
        try:
            g = NetworkGroupModel.objects.get(id=gid)
        except NetworkGroupModel.DoesNotExist:
            return err('分组不存在')
        if g.name == '默认分组':
            return err('默认分组无法编辑')
        new_name = data.get('name', g.name)
        if '/' in new_name:
            return err('分组名不支持 /')
        if NetworkGroupModel.objects.filter(name=new_name).exclude(id=gid).exists():
            return err('分组名已存在')
        for f in ('name', 'parent_id', 'description'):
            if f in data:
                setattr(g, f, data[f] if f != 'parent_id' else (data[f] or None))
        g.save()
        return ok(g.to_dict(), '信息更新成功')

    def delete(self, request):
        from apps.cmdb.models.control_models import NetworkGroupModel, NetworkEquipmentModel
        data = json.loads(request.body or b'{}')
        gid = data.get('id')
        if not gid:
            return err('id 不能为空')
        try:
            g = NetworkGroupModel.objects.get(id=gid)
        except NetworkGroupModel.DoesNotExist:
            return err('分组不存在')
        if g.name == '默认分组':
            return err('默认分组无法删除')
        if NetworkGroupModel.objects.filter(parent=g).exists():
            return err('分组下有子分组无法删除')
        if NetworkEquipmentModel.objects.filter(network_group=g).exists():
            return err('分组下有网络设备无法删除')
        g.delete()
        return ok({'id': gid}, '信息删除成功')


# ────────────────── 设备 CRUD ──────────────────
class NetworkEquipmentAllView(APIView):
    """设备列表（对齐 control network-equipment-all）
    注意：control 返回 **直接是设备数组**（data: [dev1, dev2...]），不是 {items, total} 对象！
    前端 getNetworkEquipmentAll 直接把 res.data 当数组用。
    """
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        from apps.cmdb.models.control_models import NetworkEquipmentModel
        qs = NetworkEquipmentModel.objects.all().select_related('equipment_type', 'network_group')
        keyword = request.GET.get('keyword', '').strip()
        if keyword:
            qs = qs.filter(name__icontains=keyword) | qs.filter(host__icontains=keyword) | qs.filter(ip__icontains=keyword)
        equipment_type = request.GET.get('equipment_type', '').strip()
        if equipment_type:
            qs = qs.filter(equipment_type__code=equipment_type)
        # group 过滤
        group = request.GET.get('network_group', '').strip()
        if group:
            qs = qs.filter(network_group_id=group)
        # 直接返回数组（对齐 control to_base_dict_v2）
        return ok([e.to_list_dict() for e in qs.order_by('-id')], '信息获取成功')


NetworkEquipmentInfoView = NetworkEquipmentAllView


NetworkEquipmentInfoView = NetworkEquipmentAllView


class NetworkEquipmentView(APIView):
    """设备增删改查（POST/PUT/DELETE 对齐 control network-equipment；GET 列表支持分页查询）"""
    authentication_classes = [CSRFExemptSessionAuthentication]

    # NetworkEquipmentInfoView 与 NetworkEquipmentView 共用 GET（编辑回填用 ?id=N）
    def get(self, request):
        """GET /api/control/v0_1/network-equipment/?current=1&pageSize=10 — 列表带分页（control 前端期望）
        GET /api/control/v0_1/network-equipment/?id=5 — 设备详情（编辑回填，control 前端用 id 参数拿详情）"""
        from apps.cmdb.models.control_models import NetworkEquipmentModel
        # ── id 存在 → 返回单台设备详情（编辑回填用）──
        eid = request.GET.get('id')
        if eid:
            try:
                obj = NetworkEquipmentModel.objects.select_related('equipment_type', 'network_group', 'controller').get(id=eid)
            except NetworkEquipmentModel.DoesNotExist:
                return err('网络设备不存在')
            # control to_detail_dict 风格：密码用 ****** 占位（不泄露明文）
            detail = obj.to_dict()
            detail['login_password'] = '******' if detail.get('login_password') else ''
            detail['login_privilege_password'] = '******' if detail.get('login_privilege_password') else ''
            detail['verify_password'] = '******' if detail.get('verify_password') else ''
            detail['private_key'] = '******' if detail.get('private_key') else ''
            # 详情页概览（chunk-bd37b2da getInfomationData）需要：
            #   e.data.info（NetworkSnmpInfoModel system 信息，取 sys_up_time 等）
            #   e.data.if_list（接口列表，按 if_admin_status 统计 up/down 圆环图）
            from apps.cmdb.models.control_models import NetworkSnmpInfoModel, NetworkInterfaceInfoModel
            _info = NetworkSnmpInfoModel.objects.filter(network=obj).first()
            # 详情页打开时若 CPU/内存无数据 → 自动采集一次（本地执行器 netmiko dis cpu/dis memory）
            # 保证每台设备打开详情都能看到真实 CPU/内存（不依赖手动点"刷新"）
            if (not _info or not _info.cpu_ratio) and obj.connection_type and obj.login_username:
                try:
                    from apps.cmdb.services import network_exec
                    from apps.cmdb.api.network_views import PasswordEncryption as _PE
                    _pe = _PE()
                    _lp = ''
                    try:
                        _lp = _pe.decrypt(obj.login_password) if obj.login_password else ''
                    except Exception:
                        _lp = obj.login_password or ''
                    _payload = {
                        'device_type': obj.device_type,
                        'connection_type': obj.connection_type,
                        'ip': obj.ip,
                        'ssh_timeout': int(obj.ssh_timeout or 15),
                        'login_username': obj.login_username,
                        'login_password': _lp,
                        'port': int((obj.telnet_port if obj.connection_type == 'Telnet' else obj.ssh_port) or 22),
                        'info_type_list': ['cpu_mem'],
                    }
                    _d = network_exec.local_network_scan_ssh(_payload)
                    _sub = (_d or {}).get('cpu_mem') or {}
                    _cm = _sub.get('data') if isinstance(_sub.get('data'), dict) else _sub
                    if isinstance(_cm, dict) and (_cm.get('cpu') not in (None, '') or _cm.get('mem') not in (None, '')):
                        if not _info:
                            _info = NetworkSnmpInfoModel(network=obj)
                        _info.cpu_ratio = '' if _cm.get('cpu') is None else str(_cm.get('cpu'))
                        _info.memory_ratio = '' if _cm.get('mem') is None else str(_cm.get('mem'))
                        _info.save()
                except Exception:
                    pass  # 采集失败不影响详情页打开（cpu/mem 显示 --）
            detail['info'] = {}
            if _info:
                # 只序列化标量字段（排除 FK 'network'，否则 JSON 序列化抛 TypeError）
                detail['info'] = {
                    f.name: getattr(_info, f.name, '') or ''
                    for f in NetworkSnmpInfoModel._meta.fields
                    if f.get_internal_type() not in ('ForeignKey', 'OneToOneField') and f.name != 'id'
                }
            detail['if_list'] = [i.to_dict() for i in NetworkInterfaceInfoModel.objects.filter(network=obj).order_by('if_index')]
            return ok(detail, '信息获取成功')
        try:
            page = int(request.GET.get('current', 1))
            page_size = int(request.GET.get('pageSize', 10))
        except (ValueError, TypeError):
            page, page_size = 1, 10
        qs = NetworkEquipmentModel.objects.all().select_related('equipment_type', 'network_group')
        # 搜索（对齐 control：search_type/search_data，auto_fields 三字段模糊搜）
        search_type = request.GET.get('search_type', '').strip()
        search_data = request.GET.get('search_data', '').strip()
        if search_type and search_data:
            if search_type == 'auto_fields':
                qs = qs.filter(
                    Q(name__icontains=search_data) | Q(host__icontains=search_data) | Q(ip__icontains=search_data)
                )
            else:
                qs = qs.filter(**{search_type + '__icontains': search_data})
        # 兼容旧 keyword 参数
        keyword = request.GET.get('keyword', '').strip()
        if keyword and not search_data:
            qs = qs.filter(name__icontains=keyword) | qs.filter(host__icontains=keyword) | qs.filter(ip__icontains=keyword)
        # 设备类型
        equipment_type = request.GET.get('equipment_type', '').strip()
        if equipment_type:
            try:
                qs = qs.filter(equipment_type_id=int(equipment_type))
            except (ValueError, TypeError):
                qs = qs.filter(equipment_type__code=equipment_type)
        # 分组（对齐 control：network_group__in 含子分组递归）
        group = request.GET.get('network_group', '').strip()
        if group:
            from apps.cmdb.models.control_models import NetworkGroupModel
            gq = NetworkGroupModel.objects.filter(id=group).first()
            if gq:
                group_ids = gq.get_children_group_queryset()  # self + 所有子孙
                qs = qs.filter(network_group_id__in=[g.id for g in group_ids])
            else:
                qs = qs.filter(network_group_id=group)
        # all_data=true → 全量返回（不分页）
        all_data = request.GET.get('all_data', '')
        if all_data in ('true', 'True', '1'):
            items = [e.to_list_dict() for e in qs.order_by('-id')]
            return ok(items, '信息获取成功')
        total = qs.count()
        items = [e.to_list_dict() for e in qs.order_by('-id')[(page - 1) * page_size:page * page_size]]
        # 统计（对齐 control count_dict：snmp 状态 + ssh/telnet 纳管状态 + 设备类型数）
        all_qs = NetworkEquipmentModel.objects.all()
        count_dict = {
            'all_count': all_qs.count(),
            'equipment_type_count': all_qs.exclude(equipment_type__isnull=True).values('equipment_type').distinct().count(),
            'snmp': {
                'snmp_none': all_qs.filter(snmp_version='').count() + all_qs.filter(snmp_version__isnull=True).count(),
                'snmp_0': all_qs.filter(snmp_version__isnull=False).exclude(snmp_version='').filter(snmp_state='0').count(),
                'snmp_1': all_qs.filter(snmp_state='1').count(),
                'snmp_2': all_qs.filter(snmp_state='2').count(),
            },
            'ssh_telnet': {
                'ssh_0': all_qs.filter(connection_type='SSH', ssh_state='0').count(),
                'ssh_1': all_qs.filter(connection_type='SSH', ssh_state='1').count(),
                'ssh_2': all_qs.filter(connection_type='SSH', ssh_state='2').count(),
                'telnet_0': all_qs.filter(connection_type='Telnet', telnet_state='0').count(),
                'telnet_1': all_qs.filter(connection_type='Telnet', telnet_state='1').count(),
                'telnet_2': all_qs.filter(connection_type='Telnet', telnet_state='2').count(),
                'ssh_telnet_none': all_qs.exclude(connection_type__in=['SSH', 'Telnet']).count(),
            },
        }
        # 完全对齐 control：{current, pageSize, count_dict, total, data: [设备数组]}
        return ok({
            'current': page,
            'pageSize': page_size,
            'count_dict': count_dict,
            'total': total,
            'data': items,
        }, '信息获取成功')

    @staticmethod
    def _apply_form(form_data, obj):
        """把 form/前端提交的字段写到 model。字段名与 control NetworkEquipmentBaseForm + NetworkEquipmentForm 一致"""
        # 启动懒种子：确保 FK 目标行存在（DeviceList 首次加载若没调 NetworkTypeView 可能没种子）
        from apps.cmdb.models.control_models import EquipmentTypeCMDBModel, ControllerAdmin
        if not EquipmentTypeCMDBModel.objects.exists():
            for t in [
                {'id': 1, 'code': 'ROUTER', 'name': '路由器', 'built_in': True},
                {'id': 2, 'code': 'SWITCH', 'name': '交换机', 'built_in': True},
                {'id': 3, 'code': 'FIREWALL', 'name': '防火墙', 'built_in': True},
            ]:
                EquipmentTypeCMDBModel.objects.get_or_create(id=t['id'], defaults=t)
        # 注意：ControllerAdmin 种子由 ControllerView._seed_default_controller_if_empty 统一负责
        # 基本字段映射（密码字段单独处理：****** 占位不更新、非空加密、空则清空）
        simple = ('name', 'host', 'ip', 'device_type', 'description', 'add_type',
                  'snmp_version', 'community_name', 'snmp_port',
                  'context_name', 'security_name', 'security_level',
                  'verification_protocol', 'privacy_protocol',
                  'connection_type', 'login_username',
                  'ssh_port', 'telnet_port', 'monitor_type')
        for f in simple:
            if f in form_data:
                setattr(obj, f, form_data.get(f) or '')
        # 密码字段：encrypt 存库（对齐 control clean_login_password/clean_verify_password/clean_private_key）
        _enc = PasswordEncryption()
        for pf in ('login_password', 'login_privilege_password', 'verify_password', 'private_key'):
            if pf in form_data:
                v = form_data.get(pf)
                if v == '******':
                    continue  # 编辑占位：不更新
                obj.__dict__[pf] = _enc.encrypt(v) if v else ''
        # FK
        if 'equipment_type' in form_data:
            et = form_data.get('equipment_type')
            from apps.cmdb.models.control_models import EquipmentTypeCMDBModel
            if et:
                # 前端 formData.equipment_type = dict.id + "" → 字符串 id（如 "2"）
                # 必须优先按 id 解析；字符串 code（如 'ROUTER'/'SWITCH'）才查 code
                if isinstance(et, int):
                    obj.equipment_type_id = et
                elif isinstance(et, str) and et.strip().isdigit():
                    obj.equipment_type_id = int(et.strip())
                else:
                    obj.equipment_type_id = EquipmentTypeCMDBModel.objects.filter(code=et).first().id if EquipmentTypeCMDBModel.objects.filter(code=et).exists() else None
        if 'network_group' in form_data:
            obj.network_group_id = form_data.get('network_group') or None
        elif 'group_id' in form_data:
            obj.network_group_id = form_data.get('group_id') or None
        if 'controller_id' in form_data:
            obj.controller_id = form_data.get('controller_id') or None
        # 数值字段
        for nf in ('timeout', 'ssh_timeout', 'telnet_timeout', 'api_timeout'):
            if nf in form_data:
                try:
                    setattr(obj, nf, int(form_data[nf]))
                except (ValueError, TypeError):
                    pass
        if 'is_bastion' in form_data:
            obj.is_bastion = bool(form_data['is_bastion'])

    @staticmethod
    def _sync_to_platform(obj, request):
        """v2：不再同步到管控平台。新链路下，eSight 设备只存 eSight 本地表，
        测试时直接通过 eSight ControllerAdmin 指向的 opsany-paas-proxy 调真实协议登录
        （明文密码从 eSight 库取，不再走管控平台解密）。
        """
        return

    def _to_proxy_network_dict(self, obj):
        """同步 agent 的 payload（对齐 control to_proxy_network_dict）
        密码字段存的是密文（与 control/agent 同 CONTROL_SECRET_KEY 加密），agent 端可解密。
        """
        from apps.cmdb.models.control_models import ControllerAdmin
        return {
            'id': obj.id, 'host': obj.host, 'name': obj.name, 'add_type': obj.add_type or '1',
            'device_type': obj.device_type or '',
            'controller': obj.controller.name if obj.controller else '空',
            'ip': obj.ip or '', 'timeout': obj.timeout or 5, 'ssh_timeout': obj.ssh_timeout or 5,
            'network_group': obj.network_group.get_super_group_name() if obj.network_group else '空',
            'description': obj.description or '',
            'snmp_version': obj.snmp_version or '', 'community_name': obj.community_name or '',
            'context_name': obj.context_name or '', 'security_name': obj.security_name or '',
            'snmp_port': obj.snmp_port or '', 'ssh_port': obj.ssh_port or '',
            'security_level': obj.security_level or '', 'verification_protocol': obj.verification_protocol or '',
            'verify_password': obj.verify_password or '', 'privacy_protocol': obj.privacy_protocol or '',
            'private_key': obj.private_key or '', 'connection_type': obj.connection_type or '',
            'login_username': obj.login_username or '', 'login_password': obj.login_password or '',
            'login_privilege_password': obj.login_privilege_password or '',
            'monitor_type': obj.monitor_type or '',
            'equipment_type': '{}/{}'.format(obj.equipment_type.code, obj.equipment_type.name) if obj.equipment_type else '',
        }

    def _sync_to_agent(self, obj, is_delete=False):
        """同步设备到 opsany-paas-proxy agent（对齐 control _create_or_update_proxy_network）
        agent 端按 host upsert；删除时只传 name 列表。失败不阻塞本地保存。
        """
        try:
            from apps.cmdb.models.control_models import ControllerAdmin
            if not obj.controller_id:
                return
            ctrl = ControllerAdmin.objects.filter(id=obj.controller_id).first()
            if not ctrl or not ctrl.proxy_url:
                return
            proxy = _ProxyApi(url=ctrl.proxy_url or '', access_token=ctrl.access_token or ctrl.proxy_token or '', exec_mode=_proxy_exec_mode(ctrl))
            ok1, _ = proxy.test_ping()
            if not ok1:
                logger.warning('[sync_agent] controller ping fail: %s', ctrl.proxy_url)
                return
            if is_delete:
                proxy.delete_proxy_network_equipment([obj.name])
            else:
                proxy.create_or_update_network([self._to_proxy_network_dict(obj)])
        except Exception as e:
            logger.warning('[sync_agent] error (non-fatal): %s', e)

    def post(self, request):
        from apps.cmdb.models.control_models import NetworkEquipmentModel, NetworkEquipmentLogModel
        try:
            data = json.loads(request.body or b'{}')
        except Exception:
            return err('请求参数格式错误')
        required = ('name', 'host', 'ip')
        for k in required:
            if not data.get(k):
                return err('{} 不能为空'.format(k))
        if NetworkEquipmentModel.objects.filter(host=data['host']).exists():
            return err('唯一标识不可重复')
        if NetworkEquipmentModel.objects.filter(name=data['name']).exists():
            return err('名称已存在')
        with transaction.atomic():
            obj = NetworkEquipmentModel()
            self._apply_form(data, obj)
            # NOT NULL 字段默认值（对齐 control 生产表）
            obj.add_type = obj.add_type or '1'
            obj.cpu_utilization_rate = obj.cpu_utilization_rate or '0'
            obj.memory_utilization_rate = obj.memory_utilization_rate or '0'
            obj.problem_count = obj.problem_count or 0
            obj.save()
            NetworkEquipmentLogModel.objects.create(
                equipment=obj, action='create_network', detail='自定义添加网络设备',
                user=request.user.username if request.user.is_authenticated else 'admin',
            )
        # 同步 agent（非阻塞）
        self._sync_to_agent(obj)
        return ok(obj.to_dict(), '信息创建成功')

    def put(self, request):
        from apps.cmdb.models.control_models import NetworkEquipmentModel, NetworkEquipmentLogModel
        try:
            data = json.loads(request.body or b'{}')
        except Exception:
            return err('请求参数格式错误')
        eid = data.get('id')
        if not eid:
            return err('id 不能为空')
        try:
            obj = NetworkEquipmentModel.objects.get(id=eid)
        except NetworkEquipmentModel.DoesNotExist:
            return err('网络设备不存在')
        if data.get('name') and NetworkEquipmentModel.objects.filter(name=data['name']).exclude(id=eid).exists():
            return err('设备名称已存在')
        with transaction.atomic():
            self._apply_form(data, obj)
            obj.save()
            NetworkEquipmentLogModel.objects.create(
                equipment=obj, action='update_network', detail='更新网络设备',
                user=request.user.username if request.user.is_authenticated else 'admin',
            )
        self._sync_to_agent(obj)
        return ok(obj.to_dict(), '信息更新成功')

    def delete(self, request):
        from apps.cmdb.models.control_models import NetworkEquipmentModel, NetworkBackupTaskModel
        try:
            data = json.loads(request.body or b'{}')
        except Exception:
            return err('请求参数格式错误')
        id_list = data.get('id')
        if id_list is None:
            return err('id 不能为空')
        if not isinstance(id_list, list):
            id_list = [id_list]
        delete_cmdb = data.get('delete_cmdb')
        objs = NetworkEquipmentModel.objects.filter(id__in=id_list)
        for obj in objs:
            if NetworkBackupTaskModel.objects.filter(equipment=obj).exists():
                return err('当前设备有备份任务正在执行无法删除')
        for obj in objs:
            # 同步 agent 删除（非阻塞）
            self._sync_to_agent(obj, is_delete=True)
            obj.delete()
        return ok({'id': id_list}, '信息删除成功')

# ────────────────── 网络设备测试（eSight → opsany-paas-proxy 真协议登录）─────────────────
class NetworkEquipmentTestView(APIView):
    """连接测试 — 复用 OpsAny 平台级 opsany-paas-proxy agent（完全复刻 control 链路）"""
    authentication_classes = [CSRFExemptSessionAuthentication]

    def _build_ssh_dict(self, data):
        connection_type = data.get('connection_type') or 'SSH'
        try:
            # Telnet 用 telnet_port（或通用 port），SSH 用 ssh_port（或通用 port）
            if connection_type == 'Telnet':
                port = int(data.get('telnet_port') or data.get('port') or 23)
            else:
                port = int(data.get('ssh_port') or data.get('port') or 22)
        except Exception:
            port = 23 if connection_type == 'Telnet' else 22
        return {
            'device_type': data.get('device_type'),
            'connection_type': connection_type,
            'ip': data.get('ip'),
            'ssh_timeout': int(data.get('ssh_timeout') or 15),
            'login_username': data.get('login_username'),
            'login_password': data.get('login_password'),
            'port': port,
        }

    def _build_snmp_dict(self, data):
        try:
            snmp_port = int(data.get('snmp_port') or 161)
        except Exception:
            snmp_port = 161
        return {
            'device_ip': data.get('ip'),
            'timeout': int(data.get('timeout') or 15),
            'version': data.get('snmp_version') or 'v2c',
            'community': data.get('community_name'),
            'security_level': data.get('security_level'),
            'security_name': data.get('security_name'),
            'verification_protocol': data.get('verification_protocol'),
            'privacy_protocol': data.get('privacy_protocol'),
            'verify_password': data.get('verify_password'),
            'private_key': data.get('private_key'),
            'udp_port': snmp_port,
        }

    def post(self, request):
        from apps.cmdb.models.control_models import NetworkEquipmentModel, ControllerAdmin
        try:
            data = json.loads(request.body or b'{}')
        except Exception:
            data = {}
        test_type = str(data.get('test_type', '')).lower()
        cid = data.get('controller_id')
        obj_ctrl = None
        if cid:
            try:
                obj_ctrl = ControllerAdmin.objects.get(id=cid)
            except ControllerAdmin.DoesNotExist:
                pass
        if not obj_ctrl:
            obj_ctrl = ControllerAdmin.objects.first()  # 兜底：库内首个控制器
        # obj_ctrl 可为 None（库里无任何控制器）→ _ProxyApi(controller=None) 自动走 local 执行器
        # ── 密码占位（******）→ 从库中取真实密码（解密），编辑抽屉测试不用重输 ──
        # 前端编辑回填把 login_password/verify_password/private_key 等显示为 ******，
        # 用户直接点测试时如果不替换，agent 会用 '******' 连设备导致必然失败。
        eq = None
        if data.get('id'):
            eq = NetworkEquipmentModel.objects.filter(id=data['id']).first()
        if not eq and data.get('ip'):
            eq = NetworkEquipmentModel.objects.filter(ip=data['ip']).first()
        if eq:
            _pe = PasswordEncryption()
            for fld in ('login_password', 'login_privilege_password', 'verify_password', 'private_key'):
                # 占位（******）或前端测试时根本没传（SNMP 测试只传部分字段）→ 自动从库取真实密码
                cur = data.get(fld)
                if cur == '******' or not cur:
                    enc = getattr(eq, fld, '') or ''
                    if enc:
                        try:
                            data[fld] = _pe.decrypt(enc)
                        except Exception:
                            data[fld] = ''
                    else:
                        data[fld] = ''
        proxy = _ProxyApi(url=obj_ctrl.proxy_url or '', access_token=obj_ctrl.proxy_token or '', exec_mode=_proxy_exec_mode(obj_ctrl))
        snmp_dict = self._build_snmp_dict(data) if test_type == 'snmp' else {}
        ssh_dict = self._build_ssh_dict(data) if test_type == 'ssh' else {}
        telnet_dict = self._build_ssh_dict(data) if test_type == 'telnet' else {}
        if test_type == 'api':
            ssh_dict = self._build_ssh_dict(data)
        ok_status, msg = proxy.check_network_status_v3(
            snmp_dict=snmp_dict, ssh_dict=ssh_dict, telnet_dict=telnet_dict,
        )
        if not ok_status and isinstance(msg, str):
            return JsonResponse({'code': 50000, 'message': msg, 'data': None})
        result = msg if isinstance(msg, dict) else {}
        # 找目标设备：优先 id，回退 IP（测试时常见未保存设备/IP 已有记录的设备）
        eq_id = data.get('id')
        if not eq_id and data.get('ip'):
            found = NetworkEquipmentModel.objects.filter(ip=data['ip']).first()
            if found:
                eq_id = found.id
        for k, state_field in [('snmp_ping', 'snmp'), ('ssh_ping', 'ssh'), ('telnet', 'telnet')]:
            if k in result and isinstance(result[k], dict) and eq_id:
                sub = result[k]
                try:
                    eq = NetworkEquipmentModel.objects.get(id=eq_id)
                    # 注意：前端 customRender 槽（chunk-298602d2 189817 行）语义为
                    #   1==a → 异常（红色 close-circle）、2==a → 正常（绿色 check-circle）
                    # 与 agent opsany-paas-proxy 同语义（snmp_state = "2" if status else "1"）。
                    # eSight 自己的 STATE_CHOICES 注释（'1'=Normal/'2'=Error）反向，需以**前端渲染语义为准**。
                    setattr(eq, '{}_state'.format(state_field), '2' if sub.get('status') is True else '1')
                    setattr(eq, '{}_state_message'.format(state_field), sub.get('message', '')[:200])
                    eq.save()
                except NetworkEquipmentModel.DoesNotExist:
                    pass
        return ok(result, '操作成功')


class NetworkEquipmentPingView(APIView):
    """批量联通测试 — 对齐 control get_network_equipment_info_ping
    逐台通过 _ProxyApi.check_network_status_v3 真实测 SNMP/SSH/Telnet 并回写 state。
    反语义：status=True → '2' (正常)；status=False → '1' (异常)；未连接 → '0'。
    """
    authentication_classes = [CSRFExemptSessionAuthentication]

    def post(self, request):
        from apps.cmdb.models.control_models import NetworkEquipmentModel, ControllerAdmin
        try:
            data = json.loads(request.body or b'{}')
        except Exception:
            data = {}
        ids = data.get('id_list') or ([data['id']] if data.get('id') else [])
        if not ids:
            return err('id 不能为空')
        # 缓存每 controller 的 proxy 客户端（按 url+token）
        proxy_cache = {}
        results = []
        for eq in NetworkEquipmentModel.objects.filter(id__in=ids).select_related('controller', 'equipment_type', 'network_group'):
            entry = {'id': eq.id, 'name': eq.name, 'ip': eq.ip, 'ok': False, 'states': {}}
            ctl = eq.controller
            # 不再强制绑控制器：未绑时 ctl=None → _ProxyApi(controller=None) 走本地执行器
            # 仅当数据库无任何 ControllerAdmin 记录且设备也没绑控制器时，无法执行（极少见）
            cache_key = (ctl.proxy_url or '', ctl.proxy_token or '', _proxy_exec_mode(ctl))
            if cache_key not in proxy_cache:
                proxy_cache[cache_key] = _ProxyApi(url=cache_key[0], access_token=cache_key[1], exec_mode=cache_key[2])
            proxy = proxy_cache[cache_key]
            # 数据库里密码是密文（AES-ECB+CONTROL_SECRET_KEY），传给 agent 前必须解密
            from apps.cmdb.api.network_views import PasswordEncryption
            _pe = PasswordEncryption()
            def _dec(p):
                if not p: return ''
                try: return _pe.decrypt(p)
                except Exception: return ''
            # 构造三段 dict；空就 {}
            snmp_dict = {}
            if eq.snmp_version and eq.community_name:
                snmp_dict = {
                    'device_ip': eq.ip,
                    'version': eq.snmp_version,
                    'community': eq.community_name,
                    'timeout': int(eq.timeout or 5),
                    'udp_port': int(eq.snmp_port or 161),
                }
                if eq.snmp_version == 'v3':
                    snmp_dict.update({
                        'security_level': eq.security_level or 'noAuthNoPriv',
                        'security_name': eq.security_name or '',
                        'verification_protocol': eq.verification_protocol or 'MD5',
                        'verify_password': _dec(eq.verify_password),
                        'privacy_protocol': eq.privacy_protocol or 'DES',
                        'private_key': _dec(eq.private_key),
                    })
            ssh_dict = {}
            telnet_dict = {}
            login_pwd = _dec(eq.login_password)
            if eq.connection_type == 'SSH' and eq.login_username:
                ssh_dict = {
                    'device_type': eq.device_type,
                    'connection_type': 'SSH',
                    'ip': eq.ip,
                    'ssh_timeout': int(eq.ssh_timeout or 15),
                    'login_username': eq.login_username,
                    'login_password': login_pwd,
                    'port': int(eq.ssh_port or 22),
                }
            elif eq.connection_type == 'Telnet' and eq.login_username:
                telnet_dict = {
                    'device_type': eq.device_type,
                    'connection_type': 'Telnet',
                    'ip': eq.ip,
                    'ssh_timeout': int(eq.ssh_timeout or 15),
                    'login_username': eq.login_username,
                    'login_password': login_pwd,
                    'port': int(eq.telnet_port or 23),
                }
            try:
                ok_status, msg = proxy.check_network_status_v3(
                    snmp_dict=snmp_dict, ssh_dict=ssh_dict, telnet_dict=telnet_dict,
                )
            except Exception as ex:
                entry['error'] = '{}: {}'.format(type(ex).__name__, ex)
                results.append(entry)
                continue
            if not ok_status:
                entry['error'] = msg if isinstance(msg, str) else 'agent error'
                results.append(entry)
                continue
            entry['ok'] = True
            data_resp = msg if isinstance(msg, dict) else {}
            # 回写 state（反语义：'2'=正常, '1'=异常）
            if 'snmp_ping' in data_resp and isinstance(data_resp['snmp_ping'], dict):
                sub = data_resp['snmp_ping']
                eq.snmp_state = '2' if sub.get('status') is True else '1'
                eq.snmp_state_message = (sub.get('message') or '')[:200]
                entry['states']['snmp_state'] = eq.snmp_state
            if 'ssh_ping' in data_resp and isinstance(data_resp['ssh_ping'], dict):
                sub = data_resp['ssh_ping']
                eq.ssh_state = '2' if sub.get('status') is True else '1'
                eq.ssh_state_message = (sub.get('message') or '')[:200]
                entry['states']['ssh_state'] = eq.ssh_state
            if 'telnet' in data_resp and isinstance(data_resp['telnet'], dict):
                sub = data_resp['telnet']
                eq.telnet_state = '2' if sub.get('status') is True else '1'
                eq.telnet_state_message = (sub.get('message') or '')[:200]
                entry['states']['telnet_state'] = eq.telnet_state
            eq.save()
            results.append(entry)
        return ok({'id_list': ids, 'results': results}, '联通测试完成')


class NetworkEquipmentFlushView(APIView):
    """GET/POST /network-equipment-flush/?id=N&info_type=all|ping,system,if,ip,cpu_mem,sys_log
    对齐 control NetworkEquipmentFlush.network_equipment_flush（GET 参数）：
      1. 设备 controller → _ProxyApi.test_ping → '控制器异常'
      2. agent network-snmp-scan-v2（body {host, info_type_list}）→ {type: {status, data}}
      3. _sync_*_info 写三张信息表（NetworkSnmpInfoModel / InterfaceInfo / IpInfo）
    """
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        # control 用 GET 参数调用 flush；复用完整 post 逻辑（post 内已处理 GET 参数读取）
        return self.post(request)

    def post(self, request):
        return self._flush(request)

    def _flush(self, request):
        # 完整采集逻辑在下方 post 方法；此处转发（兼容 GET/POST 双入口）
        return self.post(request)

    @staticmethod
    def _clean_system_data(d):
        return {k: d.get(k, '') for k in (
            'sys_name', 'sys_services', 'sys_location', 'sys_contact', 'sys_descr',
            'sys_up_time', 'sys_object_id', 'snmp_engine_time', 'app_version',
            'hardware_version', 'ss_cpu_idle', 'monitor_way', 'cpu_1m', 'cpu_5m',
            'cpu_5s', 'mem_total_free', 'mem_total_real', 'sys_up_datetime',
            'total_memory', 'total_used', 'used_rate', 'cpu_ratio', 'memory_ratio',
            'physical_descr', 'physical_mfg_name', 'physical_model_name',
            'physical_name', 'physical_serial_num', 'physical_software_rev',
            'sys_version',
        )}

    def post(self, request):
        from apps.cmdb.models.control_models import (
            NetworkEquipmentModel, ControllerAdmin,
            NetworkSnmpInfoModel, NetworkInterfaceInfoModel, NetworkIpInfoModel,
        )
        try:
            data = json.loads(request.body or b'{}')
        except Exception:
            data = request.GET.dict() if request.method == 'GET' else {}
        eid = data.get('id') or request.GET.get('id')
        info_type = (data.get('info_type') or request.GET.get('info_type') or 'all')
        if not eid:
            return err('参数错误')
        try:
            network = NetworkEquipmentModel.objects.select_related('controller').get(id=eid)
        except NetworkEquipmentModel.DoesNotExist:
            return err('当前网络设备不存在')
        # 设备未绑控制器也能采集（_ProxyApi controller=None 自动走 local）
        ctrl = network.controller  # 可能为 None
        proxy = _ProxyApi(url=ctrl.proxy_url if ctrl else '', access_token=ctrl.access_token or ctrl.proxy_token if ctrl else '', exec_mode=_proxy_exec_mode(ctrl))
        ok1, _ = proxy.test_ping()
        # 本地执行器（exec_mode='local'）ping 恒可用，无需拦截
        if not ok1 and _proxy_exec_mode(ctrl) == 'agent':
            return err('控制器异常')
        if info_type == 'all':
            info_type_list = ['ping', 'system', 'if', 'ip', 'cpu_mem']
        elif ',' in info_type:
            info_type_list = info_type.split(',')
        else:
            info_type_list = [info_type]
        # 调 agent network-snmp-scan/（v1：直接传 SNMP 凭据，不依赖 agent 本地设备表）
        # ⚠️ 2026-08-13 关键修复：原来调 v2（network-snmp-scan-v2/），v2 按 host 从 agent 本地库
        #   查 SNMP 凭据（query = NetworkEquipmentModel.fetch_one(host=host)），eSight 设备不在
        #   agent 库 → 返回空 dic → 详情页 if/ip/cpu 全空。v1 直接传参数，agent 端不查库。
        #   v1 内部：PasswordEncryption().decrypt(verify_password/private_key) 失败则保留明文，
        #   所以 eSight 传解密后的明文即可；udp_port 被 v1 强制 161。
        from apps.cmdb.api.network_views import PasswordEncryption as _PE
        _pe = _PE()
        def _dec2(p):
            if not p: return ''
            try: return _pe.decrypt(p)
            except Exception: return p  # 已是明文
        snmp_scan_payload = {
            'device_ip': network.ip,
            'version': network.snmp_version or 'v2c',
            'community': network.community_name or '',
            'timeout': int(network.timeout or 5),
            'info_type_list': info_type_list,
        }
        if (network.snmp_version or '') == 'v3':
            snmp_scan_payload.update({
                'security_level': network.security_level or 'noAuthNoPriv',
                'security_name': network.security_name or '',
                'verification_protocol': network.verification_protocol or 'MD5',
                'verify_password': _dec2(network.verify_password),
                'privacy_protocol': network.privacy_protocol or 'DES',
                'private_key': _dec2(network.private_key),
            })
        try:
            status, data_info = proxy._request(
                'POST', proxy.url + '/api/proxy/v0_1/network-snmp-scan/',
                data=snmp_scan_payload, timeout=120,
            )
        except Exception as e:
            return err('采集失败: {}'.format(e))
        if not isinstance(data_info, dict):
            return err('采集返回异常')
        # ping → snmp_state
        ping = data_info.get('ping') or {}
        if ping and isinstance(ping, dict):
            network.snmp_state = '2' if ping.get('status') else '1'
            network.snmp_state_message = str(ping.get('data', ''))[:200]
            network.save(update_fields=['snmp_state', 'snmp_state_message'])
        # system / cpu_mem → NetworkSnmpInfoModel
        info_dict = {}
        for key in ('system', 'cpu_mem'):
            sub = data_info.get(key) or {}
            if sub and isinstance(sub, dict) and sub.get('status'):
                sub_data = sub.get('data') or {}
                if isinstance(sub_data, dict):
                    # agent cpu_mem 返回 {cpu: X, mem: Y} → 映射到 system 表字段名
                    if key == 'cpu_mem':
                        if 'cpu' in sub_data and 'cpu_ratio' not in sub_data:
                            sub_data['cpu_ratio'] = sub_data.pop('cpu')
                        if 'mem' in sub_data and 'memory_ratio' not in sub_data:
                            sub_data['memory_ratio'] = sub_data.pop('mem')
                    info_dict.update(sub_data)
        if info_dict:
            clean = self._clean_system_data(info_dict)
            clean['network'] = network
            info_q = NetworkSnmpInfoModel.objects.filter(network=network).first()
            if info_q:
                for k, v in clean.items():
                    setattr(info_q, k, v)
                info_q.save()
            else:
                NetworkSnmpInfoModel.objects.create(**clean)
        # if → NetworkInterfaceInfoModel（if_index upsert，多余删除）
        if_info = data_info.get('if') or {}
        if if_info and isinstance(if_info, dict) and if_info.get('status'):
            # agent 返回字段分组数组 {if_index:[...], if_name:[...]} → 转对象数组
            if_list = self._cols_to_rows(if_info.get('data') or {})
            new_ids = []
            for if_data in if_list:
                if not isinstance(if_data, dict):
                    continue
                if_index = if_data.get('if_index')
                if_data['network'] = network
                q = NetworkInterfaceInfoModel.objects.filter(network=network, if_index=if_index).first()
                if q:
                    for k, v in if_data.items():
                        if k != 'network':
                            setattr(q, k, v)
                    q.save()
                    new_ids.append(q.id)
                else:
                    q = NetworkInterfaceInfoModel.objects.create(**if_data)
                    new_ids.append(q.id)
            NetworkInterfaceInfoModel.objects.filter(network=network).exclude(id__in=new_ids).delete()
        # ip → NetworkIpInfoModel（ip_net_to_media_net_address upsert，多余删除）
        ip_info = data_info.get('ip') or {}
        if ip_info and isinstance(ip_info, dict) and ip_info.get('status'):
            ip_list = self._cols_to_rows(ip_info.get('data') or {})
            new_ids = []
            for ip_data in ip_list:
                if not isinstance(ip_data, dict):
                    continue
                addr = ip_data.get('ip_net_to_media_net_address')
                ip_data['network'] = network
                q = NetworkIpInfoModel.objects.filter(network=network, ip_net_to_media_net_address=addr).first()
                if q:
                    for k, v in ip_data.items():
                        if k != 'network':
                            setattr(q, k, v)
                    q.save()
                    new_ids.append(q.id)
                else:
                    q = NetworkIpInfoModel.objects.create(**ip_data)
                    new_ids.append(q.id)
            NetworkIpInfoModel.objects.filter(network=network).exclude(id__in=new_ids).delete()
        return ok({'status': True}, '采集成功')

    @staticmethod
    def _cols_to_rows(data):
        """把 agent SNMP 返回的"字段分组数组"格式转成"对象数组"格式。
        agent network-snmp-scan 返回 {if_index: ['1','2',...], if_name: ['InLoopBack0',...], ...}
        前端/eSight 落库需要 [{if_index:'1', if_name:'InLoopBack0', ...}, ...]
        兼容：如果本来就是对象数组（dict 列表）则原样返回。
        """
        if data is None:
            return []
        if isinstance(data, list):
            return data
        if not isinstance(data, dict) or not data:
            return []
        keys = list(data.keys())
        first = data[keys[0]]
        if not isinstance(first, list):
            return [data]  # 单条 dict
        rows = []
        n = len(first)
        for i in range(n):
            row = {}
            for k in keys:
                col = data[k]
                if isinstance(col, list) and i < len(col):
                    row[k] = col[i]
                elif isinstance(col, list):
                    row[k] = ''
                else:
                    row[k] = col
            rows.append(row)
        return rows


# ────────────────── 从资源平台（真实拉取 CMDB 网络设备）─────────────────
class GetNetworkView(APIView):
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        import requests as _req
        from django.conf import settings as _s
        from apps.cmdb.models.control_models import NetworkEquipmentModel
        # 只认 bk_token（平台登录会话）；sessionid 不能当 bk_token，勿回退
        bk_token = request.COOKIES.get('bk_token') or ''
        platform = getattr(_s, 'BK_URL', 'https://192.168.99.31').rstrip('/')
        if not bk_token:
            return ok([], '信息获取成功')  # 未登录平台会话，无 bk_token
        esb_url = getattr(_s, 'PAAS_ESB_URL', None) or '{}/api'.format(platform)  # 参照 control：PAAS_ESB_URL=http://host:8002
        try:
            r = _req.get(
                '{}/c/compapi/cmdb/get_all_host_v2/'.format(esb_url.rstrip('/')),
                params={
                    'bk_app_code': getattr(_s, 'APP_CODE', 'esight'),
                    'bk_app_secret': getattr(_s, 'SECRET_KEY', ''),
                    'bk_token': bk_token,
                    'model_code': 'esb',
                    'model_code_list': 'NETWORK.all',
                },
                timeout=20, verify=False,
            )
            body = r.json()
        except Exception as e:
            # 不再静默吞错：返回真实错误便于排查（ESB 不可达/超时等）
            return err('ESB 调用失败: {}'.format(e))
        if not body.get('result'):
            return err('平台 ESB 认证失败: {}'.format(body.get('message') or body))
        result = body.get('data') or []
        managed_hosts = set(NetworkEquipmentModel.objects.values_list('host', flat=True))
        # ESB get_all_host_v2 返回格式：data = [{model_code, model_name, data_count, data:[{name, visible_name, model_code, data:{...}}]}]
        # 前端 AddFromCmdb 期望分组嵌套：[{model_code, model_name, data:[{name, show_name, ...}]}]（tab 标题 = model_name + 数量）
        # 注意：所有模型都要保留（含 data 为空的），前端 tab 才显示"路由器(0)/防火墙(0)"等空模型标签；
        # 后续在 CMDB 新增的网络设备模型（如 ACCESS_SWITCH）也会自动出现，无需改代码。
        groups = {}
        for model_inst in result:
            type_code = (model_inst.get('model_code') or '').upper()
            if not type_code:
                continue
            model_name = model_inst.get('model_name') or {
                'ROUTER': '路由器', 'SWITCH': '交换机', 'FIREWALL': '防火墙',
                'CLOUD_SERVER': '云主机', 'SERVER': '物理机', 'VIRTUAL_SERVER': '虚拟机',
            }.get(type_code, type_code)
            # 先建空分组（即使模型下无设备，tab 也要显示）
            group = groups.setdefault(type_code, {'model_name': model_name, 'data': []})
            for inst in (model_inst.get('data') or []):
                host = inst.get('name', '')
                if not host or host in managed_hosts:
                    continue
                d = inst.get('data') or {}
                # 字段前缀 = 模型 code（如 SWITCH_VISIBLE_NAME / SWITCH_ADMIN_IP / SWITCH_PUBLIC_IP / SWITCH_INTERNAL_IP）
                show_name = d.get(type_code + '_VISIBLE_NAME') or d.get(type_code + '_name') or inst.get('visible_name') or host
                ip = d.get(type_code + '_ADMIN_IP') or d.get(type_code + '_PUBLIC_IP') or d.get(type_code + '_INTERNAL_IP') or ''
                public_ip = d.get(type_code + '_PUBLIC_IP') or ''
                private_ip = d.get(type_code + '_INTERNAL_IP') or ip
                group['data'].append({
                    'name': host, 'show_name': show_name, 'host': host,
                    'ip': ip, 'public_ip': public_ip, 'private_ip': private_ip,
                    'system_type': type_code.lower(),
                    # 网络设备 host_type 直接用模型 code（SWITCH/ROUTER/FIREWALL），供前端弹窗按类型 tab 过滤
                    'host_type': type_code,
                    'manage_state': 1,
                    'tube_state': {'ssh_state': 'SSH正常', 'agent_state': '--'},
                    'control_type': ['SSH'],
                    'model_code': type_code,
                    'equipment_type': type_code,
                })
        out = [{'model_code': code, 'model_name': info['model_name'], 'data': info['data']}
               for code, info in groups.items()]
        return ok(out, '信息获取成功')


# ────────────────── 控制器（Proxy Agent）─────────────────
_OPSANY_PROXY_URL = 'https://192.168.99.31:8011'
_OPSANY_DEFAULT_TOKEN = '0f85a8c6-a1dd-48b5-af48-b5e26370ead3'


def _proxy_exec_mode(ctrl):
    """从 ControllerAdmin 对象解析执行模式：exec_mode 字段优先，type=='local' 兜底。
    'local'=eSight 进程内直连设备（netmiko+pysnmp）；其他=调平台 opsany-paas-proxy。
    ctrl=None → 默认 'local'（设备未绑控制器也能本地直连，推荐正式环境）。"""
    if ctrl is None:
        return 'local'
    m = getattr(ctrl, 'exec_mode', '') or ''
    if m in ('agent', 'local'):
        return m
    return 'local' if getattr(ctrl, 'type', '') == 'local' else 'agent'


class _ProxyApi:
    """调用 opsany-paas-proxy agent 的 HTTP 客户端（参照 control/utils/proxy_api.py 反编译）。
    exec_mode='local' 时进程内直接调 services.network_exec，不发起 HTTP。
    controller=None 时 url/token 留空，exec_mode='local'（设备未绑控制器也支持本地直连）。"""

    def __init__(self, url='', public_url='', proxy_status=True, proxy_public_status=True,
                 access_token='', exec_mode='agent', controller=None):
        if controller is not None:
            url = url or (controller.proxy_url or '')
            access_token = access_token or (controller.access_token or controller.proxy_token or '')
            exec_mode = exec_mode or _proxy_exec_mode(controller)
        self.url = (url or '').rstrip('/')
        self.public_url = (public_url or '').rstrip('/')
        self.access_token = access_token or ''
        self.exec_mode = exec_mode or 'agent'
        self.headers = {
            'Cookie': 'access={}'.format(self.access_token),
            'Content-Type': 'application/json;charset=utf-8',
        }

    def _request(self, method, url, data=None, params=None, timeout=30):
        if self.exec_mode == 'local':
            return self._local_request(url, data, params, timeout)
        import json as _json
        import requests as _req
        try:
            kwargs = {'headers': self.headers, 'timeout': timeout, 'verify': False}
            if data is not None:
                kwargs['data'] = _json.dumps(data)
            if params is not None:
                kwargs['params'] = params
            r = _req.request(method.upper(), url, **kwargs)
            try:
                body = r.json()
            except Exception:
                return False, r.text[:200] if r.text else 'non-json response'
            if r.status_code == 200 and body.get('code') in (200, 20001, '200'):
                return True, body.get('data')
            return False, body.get('message') or str(body)[:200]
        except Exception as e:
            return False, '{}: {}'.format(type(e).__name__, e)

    def _local_request(self, url, data=None, params=None, timeout=30):
        """本地执行模式：按 agent api_path 分发到 services.network_exec，返回格式与 agent 一致。"""
        from apps.cmdb.services import network_exec
        path = url.split('/api/proxy/v0_1/')[-1].lstrip('/')
        if not path:
            return False, '本地执行器: 空接口路径'
        if path == 'ht/':
            return network_exec.local_test_ping()
        if path == 'check-network-status-v3/':
            d = data or {}
            return True, network_exec.local_check_network_status_v3(
                d.get('snmp_dict'), d.get('ssh_dict'), d.get('telnet_dict'))
        if path == 'network-snmp-scan/':
            return True, network_exec.local_network_snmp_scan(data or {})
        if path == 'network-ssh-scan/':
            return True, network_exec.local_network_scan_ssh(data or {})
        if path == 'network-ssh-config/':
            return True, network_exec.local_network_ssh_config((data or {}).get('data_list') or [])
        if path == 'network-equipment/':
            # 本地模式设备库就是 eSight 自己，无需同步到 agent 库
            return True, network_exec.local_create_or_update_network(data or {})
        return False, '本地执行器未实现接口: {}'.format(path)

    def test_ping(self):
        return self._request('GET', self.url + '/api/proxy/v0_1/ht/')

    def check_network_status_v3(self, snmp_dict=None, ssh_dict=None, telnet_dict=None):
        data = {'snmp_dict': snmp_dict or {}, 'ssh_dict': ssh_dict or {}, 'telnet_dict': telnet_dict or {}}
        return self._request('POST', self.url + '/api/proxy/v0_1/check-network-status-v3/', data=data, timeout=60)

    def create_or_update_network(self, res_list):
        return self._request('POST', self.url + '/api/proxy/v0_1/network-equipment/', data=res_list, timeout=30)

    def delete_proxy_network_equipment(self, name_list):
        return self._request('DELETE', self.url + '/api/proxy/v0_1/network-equipment/', data=name_list, timeout=30)

    def subnet_mask_scan(self, subnet_mask_str, timeout=7200):
        """IP 子网扫描 — 调 agent `/api/proxy/v0_1/subnet-mask-scan/`（nmap -sL + -sn）。
        对齐 control SubnetScanComponent.subnet_scan_ip_v2 → proxy_api.subnet_mask_scan。
        返回 (True, {'ip_list_dict': {...}, 'ip_dict': {...}}) 或 (False, err)。
        """
        if self.exec_mode == 'local':
            return False, '本地执行器无 nmap 能力，请为子网选择远程控制器（默认控制器）'
        data = {'subnet_mask_str': subnet_mask_str, 'timeout': int(timeout or 7200)}
        return self._request('POST', self.url + '/api/proxy/v0_1/subnet-mask-scan/', data=data,
                             timeout=int(timeout or 7200) + 30)


def _seed_default_controller_if_empty():
    """种子两条控制器（用户 2026-08-13 明确：下拉要两个选项）：
      1. 本地执行器（exec_mode='local'，无 URL）——eSight 进程内直连设备，正式环境推荐；
      2. 默认控制器（exec_mode='agent'，指向平台 opsany-paas-proxy）——采控管理里添加的远程控制器。
    """
    from apps.cmdb.models.control_models import ControllerAdmin
    if not ControllerAdmin.objects.filter(name='本地执行器').exists():
        ControllerAdmin.objects.create(
            name='本地执行器', type='local', ip='',
            proxy_url='', proxy_public_url='',
            proxy_token='', access_token='',
            proxy_status=True, proxy_public_status=True,
            exec_mode='local',
            proxy_description='eSight 本地直连执行器（netmiko+snmpwalk），不依赖平台 agent，正式环境推荐',
            api_username='', api_password='',
        )
    if not ControllerAdmin.objects.filter(name='默认控制器').exists():
        ControllerAdmin.objects.create(
            name='默认控制器', type='proxy', ip='192.168.99.31',
            proxy_url=_OPSANY_PROXY_URL, proxy_public_url=_OPSANY_PROXY_URL,
            proxy_token=_OPSANY_DEFAULT_TOKEN, access_token=_OPSANY_DEFAULT_TOKEN,
            proxy_status=True, proxy_public_status=True,
            exec_mode='agent',
            proxy_description='OpsAny 平台 opsany-paas-proxy（远程代理，可在采控管理中修改/新增）',
            api_username='', api_password='',
        )


class ControllerView(APIView):
    authentication_classes = [CSRFExemptSessionAuthentication]

    def _serialize(self, c):
        # 字段对齐 control dist 表格列（chunk-4e5f2fd2 反编译）：
        #   Proxy名称=name / 纳管主机=count / 访问地址=url / Proxy密钥=access_token /
        #   备注=description / 链接状态=status / 类型=type（筛选用）
        return {
            'id': c.id,
            'name': c.name,
            'type': c.type or 'local',
            'count': c.count or 0,
            'url': c.proxy_url or '',
            'access_token': c.access_token or c.proxy_token or '',
            'description': c.proxy_description or '',
            'status': bool(c.proxy_status),
            'proxy_url': c.proxy_url or '',
            'proxy_public_url': c.proxy_public_url or '',
            'proxy_token': c.proxy_token or '',
            'proxy_status': bool(c.proxy_status),
            'proxy_public_status': bool(c.proxy_public_status),
            'proxy_description': c.proxy_description or '',
            'ip': c.ip or '',
            'proxy_agent_count': c.proxy_agent_count or 0,
            'api_username': c.api_username or '',
            'api_password': c.api_password or '',
        }

    def get(self, request):
        from apps.cmdb.models.control_models import ControllerAdmin
        _seed_default_controller_if_empty()
        # ?id=N → 返回单条（control dist 编辑弹窗回填调 GET /controller/?id=2）
        eid = request.GET.get('id')
        if eid:
            try:
                obj = ControllerAdmin.objects.get(id=eid)
            except ControllerAdmin.DoesNotExist:
                return err('控制器不存在')
            return ok(self._serialize(obj), '信息获取成功')
        # data=all → 对齐 control _get_salt_controller（controller_controller_decomp.py L62-77）：
        #   添加设备/IP管理/扫描等弹窗 getList({data:"all"}) 调用，返回【纯数组】不分页，
        #   前端直接 t.controllerList=e.data / e.data[0].id；分页对象会导致下拉为空。
        if request.GET.get('data') == 'all':
            items = [self._serialize(c) for c in ControllerAdmin.objects.all().order_by('id')]
            return ok(items, '信息获取成功')
        # 分页参数：control dist 用 page/per_page（chunk-4e5f2fd2: getcontolList({page, per_page, type})）
        try:
            page = int(request.GET.get('page', 1) or 1)
        except (ValueError, TypeError):
            page = 1
        try:
            per_page = int(request.GET.get('per_page', 10) or 10)
        except (ValueError, TypeError):
            per_page = 10
        ctype = request.GET.get('type') or ''
        qs = ControllerAdmin.objects.all().order_by('id')
        if ctype and ctype != 'all':
            qs = qs.filter(type=ctype)
        total = qs.count()
        items = [self._serialize(c) for c in qs[(page - 1) * per_page:page * per_page]]
        # control 前端读 e.data.data / e.data.current / e.data.pageSize / e.data.total
        return ok({'current': page, 'pageSize': per_page, 'total': total, 'data': items}, '信息获取成功')

    def post(self, request):
        from apps.cmdb.models.control_models import ControllerAdmin
        data = json.loads(request.body or b'{}')
        name = data.get('name')
        if not name:
            return err('名称不能为空')
        if ControllerAdmin.objects.filter(name=name).exists():
            return err('名称已存在')
        obj = ControllerAdmin.objects.create(
            name=name, type=data.get('type') or 'local',
            ip=data.get('ip') or '',
            proxy_url=data.get('proxy_url') or '',
            proxy_public_url=data.get('proxy_public_url') or '',
            proxy_token=data.get('proxy_token') or '',
            access_token=data.get('access_token') or data.get('proxy_token') or '',
            proxy_description=data.get('proxy_description') or '',
            api_username=data.get('api_username') or '',
            api_password=data.get('api_password') or '',
            proxy_status=True, proxy_public_status=True,
        )
        return ok(self._serialize(obj), '信息创建成功')

    def put(self, request):
        from apps.cmdb.models.control_models import ControllerAdmin
        data = json.loads(request.body or b'{}')
        cid = data.get('id')
        if not cid:
            return err('id 不能为空')
        try:
            obj = ControllerAdmin.objects.get(id=cid)
        except ControllerAdmin.DoesNotExist:
            return err('控制器不存在')
        for f in ('name', 'type', 'ip', 'proxy_url', 'proxy_public_url', 'proxy_token',
                  'access_token', 'proxy_description', 'api_username', 'api_password'):
            if f in data:
                setattr(obj, f, data[f])
        obj.save()
        return ok(self._serialize(obj), '信息更新成功')

    def delete(self, request):
        from apps.cmdb.models.control_models import ControllerAdmin
        data = json.loads(request.body or b'{}')
        cid = data.get('id')
        if not cid:
            return err('id 不能为空')
        try:
            obj = ControllerAdmin.objects.get(id=cid)
        except ControllerAdmin.DoesNotExist:
            return err('控制器不存在')
        obj.delete()
        return ok({'id': cid}, '信息删除成功')


class ControllerSaltPingView(APIView):
    authentication_classes = [CSRFExemptSessionAuthentication]

    def post(self, request):
        from apps.cmdb.models.control_models import ControllerAdmin
        data = json.loads(request.body or b'{}')
        cid = data.get('id')
        try:
            obj = ControllerAdmin.objects.get(id=cid) if cid else ControllerAdmin.objects.first()
        except ControllerAdmin.DoesNotExist:
            return err('控制器不存在')
        if not obj:
            return err('没有可用控制器')
        proxy = _ProxyApi(url=obj.proxy_url or '', access_token=obj.access_token or obj.proxy_token or '', exec_mode=_proxy_exec_mode(obj))
        ok_status, msg = proxy.test_ping()
        try:
            obj.proxy_status = ok_status
            obj.save(update_fields=['proxy_status'])
        except Exception:
            pass
        if ok_status:
            return ok({'status': True, 'message': 'Success'}, '测试通过')
        return err(msg or '连接失败')


class ControllerSaltStatusView(APIView):
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        from apps.cmdb.models.control_models import ControllerAdmin
        _seed_default_controller_if_empty()
        results = []
        for c in ControllerAdmin.objects.all():
            proxy = _ProxyApi(url=c.proxy_url or '', access_token=c.access_token or c.proxy_token or '', exec_mode=_proxy_exec_mode(c))
            ok1, msg = proxy.test_ping()
            c.proxy_status = ok1
            results.append({'id': c.id, 'name': c.name, 'proxy_status': ok1, 'message': msg})
            try:
                c.save(update_fields=['proxy_status'])
            except Exception:
                pass
        return ok(results, '信息获取成功')


class ControllerPingView(APIView):
    """POST /api/v1/control/v0_1/controller-ping/ — 连接测试（control dist 新建/编辑弹窗的"测试"按钮）
    body: {proxy_url|proxy_public_url, proxy_token, id?}
    """
    authentication_classes = [CSRFExemptSessionAuthentication]

    def post(self, request):
        from apps.cmdb.models.control_models import ControllerAdmin
        data = json.loads(request.body or b'{}')
        proxy_url = data.get('proxy_url') or ''
        proxy_token = data.get('proxy_token') or ''
        if not proxy_token:
            return err('请输入Proxy密钥')
        if not proxy_url:
            return err('请输入访问地址')
        # 有 id 时用库内记录，否则用传入参数
        url = proxy_url
        if data.get('id'):
            try:
                obj = ControllerAdmin.objects.get(id=data['id'])
                url = obj.proxy_url or url
                proxy_token = obj.access_token or obj.proxy_token or proxy_token
            except ControllerAdmin.DoesNotExist:
                pass
        proxy = _ProxyApi(url=url, access_token=proxy_token, exec_mode=_proxy_exec_mode(obj) if data.get('id') else 'agent')
        ok_status, msg = proxy.test_ping()
        if ok_status:
            return ok({'status': True, 'message': 'Success'}, '测试通过')
        return err(msg or '连接失败')


class UpdateControllerStatusView(APIView):
    """GET /api/v1/control/v0_1/update-controller-status/ — 刷新所有控制器状态（control dist 刷新按钮）"""
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        from apps.cmdb.models.control_models import ControllerAdmin
        _seed_default_controller_if_empty()
        for c in ControllerAdmin.objects.all():
            proxy = _ProxyApi(url=c.proxy_url or '', access_token=c.access_token or c.proxy_token or '', exec_mode=_proxy_exec_mode(c))
            ok1, _ = proxy.test_ping()
            c.proxy_status = ok1
            try:
                c.save(update_fields=['proxy_status'])
            except Exception:
                pass
        return ok({'status': True}, '状态刷新成功')


class ControllerTestView(APIView):
    authentication_classes = [CSRFExemptSessionAuthentication]

    def post(self, request):
        from apps.cmdb.models.control_models import ControllerAdmin
        data = json.loads(request.body or b'{}')
        cid = data.get('id')
        try:
            obj = ControllerAdmin.objects.get(id=cid) if cid else ControllerAdmin.objects.first()
        except ControllerAdmin.DoesNotExist:
            return err('控制器不存在')
        if not obj:
            return err('没有可用控制器')
        proxy = _ProxyApi(url=obj.proxy_url or '', access_token=obj.access_token or obj.proxy_token or '', exec_mode=_proxy_exec_mode(obj))
        ok_status, msg = proxy.test_ping()
        if ok_status:
            return ok({'status': True, 'message': 'Success'}, '测试通过')
        return ok({'status': False, 'message': msg or 'Failed'}, '测试失败')


class NetworkEquipmentInfoView(APIView):
    """GET /network-equipment-info/?id=N&data_type=if|ip|sys_log — 设备详情三态
    对齐 control get_network_equipment_info：
      data_type=if      → 接口列表（NetworkInterfaceInfoModel 分页，order_by if_index）
      data_type=ip      → IP 列表（NetworkIpInfoModel 分页，order_by update_time）
      data_type=sys_log → 系统日志（NetworkSnmpInfoModel.sys_log 文本）
    """
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        from apps.cmdb.models.control_models import (
            NetworkEquipmentModel, NetworkInterfaceInfoModel, NetworkIpInfoModel, NetworkSnmpInfoModel,
        )
        eid = request.GET.get('id')
        data_type = request.GET.get('data_type') or 'if'
        if not eid:
            return err('id 不能为空')
        try:
            network = NetworkEquipmentModel.objects.get(id=eid)
        except NetworkEquipmentModel.DoesNotExist:
            return err('网络设备不存在')
        try:
            page = int(request.GET.get('current', 1))
        except (ValueError, TypeError):
            page = 1
        try:
            per_page = int(request.GET.get('pageSize', 10))
        except (ValueError, TypeError):
            per_page = 10
        all_data = request.GET.get('all_data', '')
        if data_type == 'sys_log':
            info = NetworkSnmpInfoModel.objects.filter(network=network).first()
            return ok(info.sys_log if info and info.sys_log else '', '信息获取成功')
        if data_type == 'ip':
            qs = NetworkIpInfoModel.objects.filter(network=network).order_by('update_time')
            serializer = lambda o: o.to_dict()
        else:  # if
            qs = NetworkInterfaceInfoModel.objects.filter(network=network).order_by('if_index')
            serializer = lambda o: o.to_dict()
        if all_data in ('true', 'True', '1'):
            return ok([serializer(o) for o in qs], '信息获取成功')
        total = qs.count()
        items = [serializer(o) for o in qs[(page - 1) * per_page:page * per_page]]
        return ok({'current': page, 'pageSize': per_page, 'total': total, 'data': items}, '信息获取成功')


# NetworkEquipmentInfoView 已实现为真正的三态详情类（上方）


class NetworkEquipmentFlushV2View(APIView):
    """GET /network-equipment-flush-v2/?id=N&info_type=sys_log,cpu_mem
    详情页打开/刷新时自动调用（chunk-bd37b2da equipmentFlushV2）。
    采集两类实时数据（复用 opsany-paas-proxy 参数直传接口，不依赖 agent 本地库）：
      - cpu_mem：agent network-snmp-scan（v1 直传 SNMP 凭据）→ cpu_ratio/memory_ratio
      - sys_log：agent network-scan-ssh（v1 直传 SSH/Telnet 凭据）→ sys_log 文本
    """
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        from apps.cmdb.models.control_models import NetworkEquipmentModel, NetworkSnmpInfoModel
        data = request.GET.dict()
        eid = data.get('id')
        info_type = data.get('info_type') or 'sys_log,cpu_mem'
        info_type_list = [x.strip() for x in str(info_type).split(',') if x.strip()]
        if not eid:
            return err('参数错误')
        try:
            network = NetworkEquipmentModel.objects.select_related('controller').get(id=eid)
        except NetworkEquipmentModel.DoesNotExist:
            return err('当前网络设备不存在')
        # 设备未绑控制器也能采集（_ProxyApi controller=None 自动走 local）
        ctrl = network.controller  # 可能为 None
        proxy = _ProxyApi(url=ctrl.proxy_url if ctrl else '', access_token=ctrl.access_token or ctrl.proxy_token if ctrl else '', exec_mode=_proxy_exec_mode(ctrl))
        from apps.cmdb.api.network_views import PasswordEncryption as _PE
        _pe = _PE()
        def _dec(p):
            if not p:
                return ''
            try:
                return _pe.decrypt(p)
            except Exception:
                return p  # 已是明文

        result = {}
        # ── 1. cpu_mem：本地执行器直采（netmiko dis cpu/dis memory，拿真实 CPU/内存）──
        # 注意：不走 proxy（agent 端 get_cup_memory 有解析 bug 返回空；本地 get_cpu_mem 精确解析）
        if 'cpu_mem' in info_type_list and network.connection_type and network.login_username:
            from apps.cmdb.services import network_exec
            payload = {
                'device_type': network.device_type,
                'connection_type': network.connection_type,
                'ip': network.ip,
                'ssh_timeout': int(network.ssh_timeout or 15),
                'login_username': network.login_username,
                'login_password': _dec(network.login_password),
                'port': int((network.telnet_port if network.connection_type == 'Telnet' else network.ssh_port) or 22),
                'info_type_list': ['cpu_mem'],
            }
            d = network_exec.local_network_scan_ssh(payload)
            # d = {'cpu_mem': {'status': True, 'data': {'cpu': '17', 'mem': '51'}}}
            sub = (d or {}).get('cpu_mem') or {}
            cm = (sub.get('data') if isinstance(sub.get('data'), dict) else sub)
            if isinstance(cm, dict) and (cm.get('cpu') not in (None, '') or cm.get('mem') not in (None, '')):
                info_q = NetworkSnmpInfoModel.objects.filter(network=network).first()
                if not info_q:
                    info_q = NetworkSnmpInfoModel(network=network)
                info_q.cpu_ratio = '' if cm.get('cpu') is None else str(cm.get('cpu'))
                info_q.memory_ratio = '' if cm.get('mem') is None else str(cm.get('mem'))
                info_q.save()
                result['cpu_mem'] = cm
        # ── 2. sys_log：SSH/Telnet 直传 ──
        if 'sys_log' in info_type_list and network.connection_type and network.login_username:
            ssh_payload = {
                'device_type': network.device_type,
                'connection_type': network.connection_type,
                'ip': network.ip,
                'ssh_timeout': int(network.ssh_timeout or 15),
                'login_username': network.login_username,
                'login_password': _dec(network.login_password),
                'port': int((network.telnet_port if network.connection_type == 'Telnet' else network.ssh_port) or 22),
                'info_type_list': ['sys_log'],
            }
            ok_status, d = proxy._request(
                'POST', proxy.url + '/api/proxy/v0_1/network-ssh-scan/',
                data=ssh_payload, timeout=90,
            )
            sub = (d or {}).get('sys_log') or {} if isinstance(d, dict) else {}
            if ok_status and isinstance(sub, dict) and sub.get('status'):
                log_data = sub.get('data') or {}
                info_q = NetworkSnmpInfoModel.objects.filter(network=network).first()
                if not info_q:
                    info_q = NetworkSnmpInfoModel(network=network)
                # data 可能是 {log: [...]} 或字符串
                # 前端详情页 logList = sys_log.split('%').reverse().slice(0,7) → 必须用 '%' 拼接
                if isinstance(log_data, dict):
                    log_list = log_data.get('log') or []
                    if isinstance(log_list, list):
                        text = '%'.join(str(x) for x in log_list)
                    else:
                        text = str(log_list or '')
                else:
                    text = str(log_data or '')
                info_q.sys_log = text
                info_q.save()
                result['sys_log'] = text
        return ok(result, '采集成功')


class NetworkConfigDiffView(APIView):
    """GET /network-config-diff/?host=X — 配置对比（详情页"配置对比" tab 数据源）
    返回 {boot_config_content, running_config_content}（对齐 control get_network_config）
    """
    authentication_classes = [CSRFExemptSessionAuthentication]

    def get(self, request):
        from apps.cmdb.models.control_models import NetworkEquipmentModel, NetworkConfigModel
        host = request.GET.get('host')
        if not host:
            return err('参数错误')
        dic = {'boot_config_content': '', 'running_config_content': ''}
        eq = NetworkEquipmentModel.objects.filter(host=host).first()
        if eq:
            cfg = NetworkConfigModel.objects.filter(network=eq).order_by('-id').first()
            if cfg:
                dic = cfg.to_diff_config()
        return ok(dic, '信息获取成功')


class NetworkPullConfigView(APIView):
    """GET /network-pull-config/?network_id=N&config_type=run|boot — 拉取设备配置
    对齐 control _network_config：
      1. 设备 → 备份策略脚本（无则用内置默认脚本）
      2. 先同步设备到 agent 库（create_or_update_network，让 agent network-ssh-config 能按 host 查凭据）
      3. 调 agent network-ssh-config → {host: {boot_status, run_status, boot_config_content, running_config_content}}
      4. 写 NetworkConfigModel（供 network-config-diff 读）
    """
    authentication_classes = [CSRFExemptSessionAuthentication]

    # 内置默认脚本（华为/H3C 等；无备份策略时兜底）
    DEFAULT_BOOT_SCRIPT = 'screen-length 0 temporary\ndisplay saved-configuration'
    DEFAULT_RUN_SCRIPT = 'screen-length 0 temporary\ndisplay current-configuration'

    def get(self, request):
        from apps.cmdb.models.control_models import (
            NetworkEquipmentModel, NetworkConfigModel, ControllerAdmin,
        )
        import datetime
        data = request.GET.dict()
        network_id = data.get('network_id')
        config_type = data.get('config_type', 'boot')
        if not network_id:
            return err('参数错误')
        eq = NetworkEquipmentModel.objects.filter(id=network_id).select_related('controller').first()
        if not eq:
            return err('当前网络设备不存在')
        if not eq.controller:
            return err('控制器不存在')
        proxy = _ProxyApi(url=eq.controller.proxy_url or '', access_token=eq.controller.access_token or eq.controller.proxy_token or '', exec_mode=_proxy_exec_mode(eq.controller))
        ok1, _ = proxy.test_ping()
        if not ok1:
            return err('控制器异常')
        # 脚本：设备未绑定备份策略（eSight 暂无该绑定），直接用内置默认脚本
        if config_type == 'boot':
            script = self.DEFAULT_BOOT_SCRIPT
        else:
            script = self.DEFAULT_RUN_SCRIPT
        # 先同步设备到 agent 库（幂等 upsert，agent 端按 host 存取）
        try:
            proxy.create_or_update_network([NetworkEquipmentView._to_proxy_network_dict(eq)])
        except Exception:
            pass
        # 调 agent network-ssh-config（按 host 查凭据）
        d = {'host': eq.host}
        if config_type == 'boot':
            d['boot_config_script'] = script
        else:
            d['running_config_script'] = script
        ok_status, res_dic = proxy._request(
            'POST', proxy.url + '/api/proxy/v0_1/network-ssh-config/',
            data={'data_list': [d]}, timeout=120,
        )
        if not ok_status:
            return err('拉取配置失败: {}'.format(str(res_dic)[:200]))
        config_dict = (res_dic or {}).get(eq.host) or {}
        boot_status = config_dict.get('boot_status')
        run_status = config_dict.get('run_status')
        boot_content = config_dict.get('boot_config_content')
        run_content = config_dict.get('running_config_content')
        if config_type == 'boot' and not boot_status:
            return err('当前网络设备拉取启动配置失败: {}'.format(str(boot_content)[:200]))
        if config_type == 'run' and not run_status:
            return err('当前网络设备拉取运行配置失败: {}'.format(str(run_content)[:200]))
        # 写 NetworkConfigModel（按网络设备 upsert 单行）
        now = datetime.datetime.now()
        username = request.user.username if request.user.is_authenticated else 'admin'
        cfg = NetworkConfigModel.objects.filter(network=eq).first()
        if not cfg:
            cfg = NetworkConfigModel(network=eq)
        if config_type == 'boot':
            cfg.boot_task_type = '4'
            cfg.boot_start_time = now
            cfg.boot_end_time = now
            cfg.boot_config_script = script
            cfg.boot_config_content = boot_content or ''
            cfg.boot_username = username
        else:
            cfg.run_task_type = '4'
            cfg.run_start_time = now
            cfg.run_end_time = now
            cfg.running_config_script = script
            cfg.running_config_content = run_content or ''
            cfg.run_username = username
        cfg.save()
        return ok({'config_type': config_type}, '配置拉取成功')
