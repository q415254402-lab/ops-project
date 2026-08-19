# -*- coding: utf-8 -*-
"""
eSight IP 地址管理视图（复刻 OpsAny control ip_manager 模块）
- 覆盖 control 前端需要的 8 个接口：
  subnet-mask/ ip-manager-group/ ip-manager/ ip-address/ ip-overview/
  subnet-mask-scan/ subnet-mask-scan-state/ ip-port-scan/ ip-port-scan-result/
- 数据本地落库（v2 路线，与网络设备模块一致）
- 子网掩码常量对齐 control constants.SUBNET_MASK_API_DICT
"""
import copy
import datetime
import ipaddress
import json
import logging
import threading

from django.db.models import Q
from django.http import JsonResponse

from apps.cmdb.models.ip_management import (
    IpSubnetManagerGroupModel, IpSubnetManagerModel, IpAddressModel,
    IpManagerScanLogModel,
)
from apps.cmdb.models.control_models import ControllerAdmin
from apps.cmdb.api.network_views import _ProxyApi, _proxy_exec_mode

logger = logging.getLogger('app')

# ── 子网掩码选项（完整改造版，2026-08-14）─────────────────────────────
# control 原版 SUBNET_MASK_API_DICT 只有 16~31 位（B/C 类），缺 8~15 位（A 类），
# 且前端 getSubnetMaskList() 调 subnet-mask/ 无参（默认 ip_type='C'）→ 下拉只剩 24~31。
# 完整改造：程序化生成 8~31 位全部掩码（A 8~15 / B 16~23 / C 24~31），
# 无参/ip_type=all 返回全部，ip_type=A/B/C 返回对应类；ip_count 用 ipaddress 自动计算。
import ipaddress as _ipaddr


def _gen_subnet_mask_list():
    """程序化生成 8~31 位完整掩码列表（A/B/C 三类的掩码是连续位模式）"""
    out = []
    for bits in range(8, 32):
        mask_int = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
        mask_str = str(_ipaddr.IPv4Address(mask_int))
        # 可用 IP 数：/31 特例对齐 control 原版为 2（RFC3021 点对点无网络/广播号）
        if bits == 31:
            ip_count = 2
        else:
            ip_count = 2 ** (32 - bits) - 2
        if bits <= 15:
            ip_type = 'A'
        elif bits <= 23:
            ip_type = 'B'
        else:
            ip_type = 'C'
        out.append({
            'subnet_mask': '"{}"'.format(mask_str),
            'mask_count': bits,
            'ip_count': ip_count,
            'ip_type': '"{}"'.format(ip_type),
        })
    return out


SUBNET_MASK_API_DICT = {
    'subnet_mask_list': _gen_subnet_mask_list(),
    'ip_type_a_max': '10.0.0.0',
    'ip_type_a_min': '126.255.255.255',
    'ip_type_b_max': '172.16.0.0',
    'ip_type_b_min': '17.31.255.255',
    'ip_type_c_max': '192.168.0.0',
    'ip_type_c_min': '192.168.255.255',
}

# 掩码字符串 → CIDR 位数（对齐 control constants.SUBNET_MASK_DICT，8~31 全量）
SUBNET_MASK_DICT = {i['subnet_mask'].strip('"'): i['mask_count'] for i in SUBNET_MASK_API_DICT['subnet_mask_list']}

# 子网扫描线程注册表（key=子网id，value=thread）—— eSight 无可靠 Celery broker，
# 用线程执行扫描（对齐 control 的 Celery 语义：可停止、可轮询状态）
# ⚠️ uwsgi 多 worker 下 locmem/内存缓存不共享，扫描状态统一存 sqlite（scan_log 表伪记录），
#    保证任意 worker 轮询都能读到（对齐 control 的 redis 语义）。
_SCAN_THREADS = {}
_SCAN_STOP_EVENTS = {}  # key=子网id, value=threading.Event（停止标志）
_SCAN_THREADS_LOCK = threading.Lock()
_CACHE_KEY_EX = 24 * 3600  # redis/内存缓存 key 有效期 24h
_STATE_SCAN_TYPE = '__scan_state__'


def _scan_cache_set(key, value):
    """跨 worker 状态存储：存 sqlite scan_log 表（scan_type='__scan_state__', request_id=cache_key）
    对齐 control 的 redis set(cache_key, value, ex=CACHE_KEY_EX)
    ⚠️ ip_manager_id NOT NULL：从 cache_key 'ip_subnet_scan_<id>' 解析子网 id 填充"""
    ip_manager_id = None
    try:
        if key.startswith('ip_subnet_scan_'):
            ip_manager_id = int(key.split('ip_subnet_scan_')[1].split('_')[0])
        elif key.endswith('_task'):
            ip_manager_id = int(key.replace('ip_subnet_scan_', '').replace('_task', ''))
    except Exception:
        pass
    try:
        defaults = {'subnet_addr': key, 'initial_data': str(value), 'scan_message': 'state'}
        if ip_manager_id:
            defaults['ip_manager_id'] = ip_manager_id
        else:
            defaults['ip_manager_id'] = 0  # 兜底（正常不会走到）
        IpManagerScanLogModel.objects.update_or_create(
            request_id=key, scan_type=_STATE_SCAN_TYPE,
            defaults=defaults)
        return
    except Exception as e:
        logger.warning('[ip_scan_cache] set %s err: %s', key, e)
    try:
        from django.core.cache import cache
        cache.set(key, value, _CACHE_KEY_EX)
    except Exception:
        pass


def _scan_cache_get(key):
    try:
        row = IpManagerScanLogModel.objects.filter(
            request_id=key, scan_type=_STATE_SCAN_TYPE).first()
        if row and row.initial_data:
            return row.initial_data
    except Exception:
        pass
    try:
        from django.core.cache import cache
        return cache.get(key)
    except Exception:
        pass
    return None


def _scan_cache_delete(key):
    try:
        IpManagerScanLogModel.objects.filter(
            request_id=key, scan_type=_STATE_SCAN_TYPE).delete()
    except Exception:
        pass
    try:
        from django.core.cache import cache
        cache.delete(key)
    except Exception:
        pass


def _is_scan_stopped(subnet_id):
    """子网扫描是否已被手动终止（停止标志）"""
    _SCAN_THREADS_LOCK.acquire()
    try:
        ev = _SCAN_STOP_EVENTS.get(str(subnet_id))
        return ev is not None and ev.is_set()
    finally:
        _SCAN_THREADS_LOCK.release()


def _ok(data=None, msg='信息获取成功'):
    if data is None:
        data = {}
    return JsonResponse({'code': 200, 'successcode': 20005, 'message': msg, 'data': data})


def _err(msg):
    return JsonResponse({'code': 400, 'successcode': 40001, 'message': msg, 'data': None})


# ── subnet-mask/ 子网掩码选项 ─────────────────────────────────────
def subnet_mask_view(request):
    """GET /subnet-mask/?ip_type=all|A|B|C — 掩码下拉选项
    完整改造（2026-08-14）：无参默认 all 返回 8~31 位全部 24 项
    （control 原版无参默认 C 只返回 24~31 → 8~23 无法选择）；
    ip_type=A/B/C 时返回对应类（A 8~15 / B 16~23 / C 24~31）。
    """
    ip_type = request.GET.get('ip_type', 'all')
    data = copy.deepcopy(SUBNET_MASK_API_DICT)
    if ip_type != 'all':
        # control 的 ip_type 值带引号（'"C"'），兼容两种
        data['subnet_mask_list'] = [i for i in data['subnet_mask_list']
                                    if ip_type.strip('"') == i.get('ip_type', '').strip('"')]
    return _ok(data)


# ── ip-manager-group/ 分组 CRUD ────────────────────────────────────
def ip_manager_group_view(request):
    """GET/POST/PUT/DELETE /ip-manager-group/"""
    if request.method == 'GET':
        return _get_ip_manager_group(request)
    if request.method == 'POST':
        return _create_ip_manager_group(request)
    if request.method == 'PUT':
        return _update_ip_manager_group(request)
    if request.method == 'DELETE':
        return _delete_ip_manager_group(request)
    return _err('不支持的请求方法')


def _get_ip_manager_group(request):
    group_list = [g.to_parent_dict() for g in
                  IpSubnetManagerGroupModel.objects.filter(parent=None).order_by('create_time')]
    return _ok(group_list)


def _create_ip_manager_group(request):
    try:
        data = json.loads(request.body)
    except Exception:
        return _err('参数错误')
    name = (data.get('name') or '').strip()
    if not name:
        return _err('分组名不能为空')
    if IpSubnetManagerGroupModel.objects.filter(name=name).exists():
        return _err('分组名已存在')
    parent_id = data.get('parent') or data.get('parent_id')
    parent = None
    if parent_id:
        parent = IpSubnetManagerGroupModel.objects.filter(id=parent_id).first()
        if not parent:
            return _err('父分组不存在')
    group = IpSubnetManagerGroupModel.objects.create(name=name, parent=parent)
    return _ok(group.to_base_dict(), '创建成功')


def _update_ip_manager_group(request):
    try:
        data = json.loads(request.body)
    except Exception:
        return _err('参数错误')
    group_id = data.get('id')
    group = IpSubnetManagerGroupModel.objects.filter(id=group_id).first()
    if not group:
        return _err('分组不存在')
    if group.name == '默认分组':
        return _err('默认分组无法编辑')
    name = (data.get('name') or '').strip()
    if not name:
        return _err('分组名不能为空')
    dup = IpSubnetManagerGroupModel.objects.filter(name=name).exclude(id=group.id).first()
    if dup:
        return _err('分组名已存在')
    group.name = name
    group.save()
    return _ok(group.to_base_dict(), '更新成功')


def _delete_ip_manager_group(request):
    try:
        data = json.loads(request.body)
    except Exception:
        data = {}
    group_id = data.get('id')
    group = IpSubnetManagerGroupModel.objects.filter(id=group_id).first()
    if not group:
        return _err('分组不存在')
    if group.name == '默认分组':
        return _err('默认分组无法删除')
    if IpSubnetManagerGroupModel.objects.filter(parent=group).exists():
        return _err('分组下有子分组无法删除')
    if IpSubnetManagerModel.objects.filter(ip_manager_group=group).exists():
        return _err('分组下有子网地址无法删除')
    group.delete()
    return _ok(None, '删除成功')


# ── ip-manager/ 子网 CRUD + 列表 ───────────────────────────────────
def ip_manager_view(request):
    """GET/POST/PUT/DELETE /ip-manager/"""
    if request.method == 'GET':
        return _get_ip_manager(request)
    if request.method == 'POST':
        return _create_ip_manager(request)
    if request.method == 'PUT':
        return _update_ip_manager(request)
    if request.method == 'DELETE':
        return _delete_ip_manager(request)
    return _err('不支持的请求方法')


def _get_ip_manager(request):
    kwargs = request.GET.dict()
    subnet_id = kwargs.get('id')
    if subnet_id:
        subnet = IpSubnetManagerModel.objects.filter(id=subnet_id).first()
        if not subnet:
            return _err('子网地址不存在')
        return _ok(subnet.to_dict())

    all_data = kwargs.pop('all_data', None)
    search_type = kwargs.pop('search_type', None)
    search_data = kwargs.pop('search_data', None)
    try:
        page = int(kwargs.pop('current', 1))
        per_page = int(kwargs.pop('pageSize', 10))
    except Exception:
        page, per_page = 1, 10

    qs = IpSubnetManagerModel.objects.all()
    ip_manager_group = kwargs.pop('ip_manager_group', None)
    if ip_manager_group:
        group = IpSubnetManagerGroupModel.objects.filter(id=ip_manager_group).first()
        if group:
            qs = qs.filter(ip_manager_group__in=group.get_children_group_queryset())
    if search_type and search_data:
        qs = qs.filter(**{search_type + '__icontains': search_data})

    if all_data:
        data = [s.to_dict() for s in qs.order_by('-create_time')]
        return _ok(data)

    total = qs.count()
    ordered_qs = qs.order_by('-create_time')
    current_page = ordered_qs[((page - 1) * per_page):(page * per_page)]
    # ⚠️ 2026-08-14 修复：count_dict 必须遍历全量（对齐 control 遍历 query_set），
    # 不能只统计当前页——子网数 > pageSize 时统计卡（总数/正常/异常/未扫描/控制器）会错
    controller_list = []
    count_dict = {'total': total, 'not_scan': 0, 'scanning': 0, 'scanned': 0, 'scan_fail': 0}
    for query in ordered_qs:
        scan_status = query.scan_status
        if scan_status == 'not_scan':
            count_dict['not_scan'] += 1
        elif scan_status == 'scanning':
            count_dict['scanning'] += 1
        elif scan_status == 'scanned':
            count_dict['scanned'] += 1
        else:
            count_dict['scan_fail'] += 1
        controller = query.controller
        if controller and controller not in controller_list:
            controller_list.append(controller)
    count_dict['controller_count'] = len(controller_list)
    res = {
        'current': page, 'pageSize': per_page, 'total': total,
        'count_dict': count_dict,
        'data': [s.to_dict() for s in current_page],
    }
    return _ok(res)


def _create_ip_manager(request):
    try:
        data = json.loads(request.body)
    except Exception:
        return _err('参数错误')
    name = (data.get('name') or '').strip()
    if not name:
        return _err('名称不能为空')
    if IpSubnetManagerModel.objects.filter(name=name).exists():
        return _err('名称已存在')
    subnet_addr = data.get('subnet_addr') or ''
    subnet_mask = data.get('subnet_mask') or ''
    # 掩码可能是 '"255.255.255.0"'（带引号）或 '255.255.255.0'
    subnet_mask = subnet_mask.strip('"')
    if not subnet_addr or not subnet_mask:
        return _err('子网地址和子网掩码不能为空')

    group_id = data.get('ip_manager_group') or data.get('ip_manager')
    group = None
    if group_id:
        group = IpSubnetManagerGroupModel.objects.filter(id=group_id).first()
    if not group:
        # 无分组时落到「默认分组」
        group = IpSubnetManagerGroupModel.objects.filter(name='默认分组').first()
    if not group:
        group = IpSubnetManagerGroupModel.objects.create(name='默认分组')

    controller_id = data.get('controller')
    controller = None
    if controller_id:
        controller = ControllerAdmin.objects.filter(id=controller_id).first()

    subnet = IpSubnetManagerModel.objects.create(
        name=name,
        description=data.get('description') or '',
        subnet_addr=subnet_addr,
        subnet_mask=subnet_mask,
        timeout=int(data.get('timeout') or 300),
        add_type=data.get('add_type') or '手动添加',
        vlan_name=data.get('vlan_name') or '',
        location=data.get('location') or '',
        controller=controller,
        ip_manager_group=group,
        scan_status='not_scan',
    )
    return _ok(subnet.to_base_dict(), '创建成功')


def _update_ip_manager(request):
    try:
        data = json.loads(request.body)
    except Exception:
        return _err('参数错误')
    subnet_id = data.pop('id', None)
    if not subnet_id:
        return _err('参数错误')
    subnet = IpSubnetManagerModel.objects.filter(id=subnet_id).first()
    if not subnet:
        return _err('数据不存在')
    name = (data.get('name') or '').strip()
    if not name:
        return _err('名称不能为空')
    dup = IpSubnetManagerModel.objects.filter(name=name).exclude(id=subnet.id).first()
    if dup:
        return _err('名称已存在')
    if 'subnet_mask' in data and data.get('subnet_mask'):
        data['subnet_mask'] = str(data['subnet_mask']).strip('"')
    for k, v in data.items():
        if hasattr(subnet, k) and k not in ('id', 'controller', 'ip_manager_group', 'ip_manager'):
            setattr(subnet, k, v)
    group_id = data.get('ip_manager_group') or data.get('ip_manager')
    if group_id:
        group = IpSubnetManagerGroupModel.objects.filter(id=group_id).first()
        if group:
            subnet.ip_manager_group = group
    controller_id = data.get('controller')
    if controller_id:
        ctrl = ControllerAdmin.objects.filter(id=controller_id).first()
        subnet.controller = ctrl
    subnet.save()
    return _ok(subnet.to_base_dict(), '更新成功')


def _delete_ip_manager(request):
    try:
        data = json.loads(request.body)
    except Exception:
        data = {}
    id_list = data.get('id')
    if not isinstance(id_list, list):
        id_list = [id_list]
    id_list = [i for i in id_list if i]
    if not id_list:
        return _err('数据不存在')
    qs = IpSubnetManagerModel.objects.filter(id__in=id_list)
    if not qs.exists():
        return _err('数据不存在')
    qs.delete()
    return _ok(None, '删除成功')


# ── ip-address/ IP 地址列表（扫描落库，不手工增删）────────────────
def ip_address_view(request):
    """GET/POST/PUT/DELETE /ip-address/"""
    if request.method == 'GET':
        return _get_ip_address(request)
    # control 语义：IP 由扫描自动落库，POST/PUT/DELETE 原样返回 success
    return _ok(None, '操作成功')


def _get_ip_address(request):
    kwargs = request.GET.dict()
    addr_id = kwargs.get('id')
    ip_manager = kwargs.get('ip_manager')
    state = kwargs.get('state')
    ip_address = kwargs.get('ip_address')
    try:
        if addr_id:
            addr_id = int(addr_id)
        if ip_manager:
            ip_manager = int(ip_manager)
    except Exception:
        return _err('参数错误')

    if addr_id:
        ip_query = IpAddressModel.objects.filter(id=addr_id).first()
        if not ip_query:
            return _err('IP地址不存在')
        return _ok(ip_query.to_detail_dict())

    all_data = kwargs.pop('all_data', None)
    search_type = kwargs.pop('search_type', None)
    search_data = kwargs.pop('search_data', None)
    try:
        page = int(kwargs.pop('current', 1))
        per_page = int(kwargs.pop('pageSize', 10))
    except Exception:
        page, per_page = 1, 10

    ip_manager_query = IpSubnetManagerModel.objects.filter(id=ip_manager).first()
    if not ip_manager_query:
        return _err('子网地址不存在')

    qs = IpAddressModel.objects.filter(ip_manager=ip_manager_query)
    if search_type and search_data:
        qs = qs.filter(**{search_type + '__icontains': search_data})
    if state:
        qs = qs.filter(state__icontains=state)
    if ip_address:
        qs = qs.filter(ip_address__icontains=ip_address)
    qs = qs.order_by('create_time')

    if all_data:
        return _ok([i.to_status_dict() for i in qs])
    total = qs.count()
    current_page = qs[(page - 1) * per_page:page * per_page]
    res = {'current': page, 'pageSize': per_page, 'total': total,
           'data': [i.to_dict() for i in current_page]}
    return _ok(res)


# ── ip-overview/ IP 概览 ───────────────────────────────────────────
def ip_overview_view(request):
    """GET /ip-overview/?ip_manager=&current=&pageSize=&all_data=
    ⚠️ 2026-08-14 修复：前端详情页 getIpOverview() 硬编码 pageSize:256 且无分页/加载更多 UI，
    control 原版受此限制概览永远只显示前 256 个 IP（/23 等大网段后半段丢失）。
    改造：概览语义=看全貌，返回该子网全部 IP（忽略 current/pageSize 分页）。
    """
    kwargs = request.GET.dict()
    ip_manager = kwargs.get('ip_manager')
    try:
        if ip_manager:
            ip_manager = int(ip_manager)
    except Exception:
        return _err('参数错误')
    ip_manager_query = IpSubnetManagerModel.objects.filter(id=ip_manager).first()
    if not ip_manager_query:
        return _err('子网地址不存在')
    qs = IpAddressModel.objects.filter(ip_manager=ip_manager_query).order_by('create_time')
    data = [i.to_overview_dict() for i in qs]
    # ⚠️ 2026-08-14 修复：响应必须嵌套 {data:{data:[...]}}，否则前端 `a.data.data` 拿不到 IP 列表，
    # 兜底为 [] → overViewData 为空 → watch 不触发 → 「子网信息概览」小卡片 0/0 + 色块全空
    return _ok({'current': 1, 'pageSize': len(data), 'total': len(data), 'data': data})


# ── subnet-mask-scan/ + subnet-mask-scan-state/ 扫描 ──────────────
def _run_subnet_scan(subnet, cache_key):
    """线程内执行子网扫描（对齐 control SubnetScanComponent.subnet_scan_ip_v2）：
    1. controller 校验 → 2. 拼 CIDR → 3. agent nmap 扫描 → 4. 回写 IP 表 + 统计
    """
    controller = subnet.controller
    scan_message = ''
    if not controller:
        scan_message = '控制器不能为空，扫描失败！'
    elif not controller.proxy_status and not controller.proxy_public_status:
        scan_message = '控制器异常，扫描失败！'
    subnet_addr = subnet.subnet_addr
    subnet_mask = subnet.subnet_mask
    timeout = subnet.timeout or 7200
    if not subnet_addr or not subnet_mask:
        scan_message = '子网地址或子网掩码不能为空，扫描失败！'
    if subnet_mask not in SUBNET_MASK_DICT:
        scan_message = '不支持的子网掩码，扫描失败！'

    if scan_message:
        IpSubnetManagerModel.objects.filter(id=subnet.id).update(
            scan_status='scan_fail', scan_message=scan_message)
        _scan_cache_set(cache_key, 'true')
        return

    try:
        proxy_api = _ProxyApi(controller=controller, exec_mode=_proxy_exec_mode(controller))
        mask_count = SUBNET_MASK_DICT.get(subnet_mask, 24)
        subnet_mask_str = '{}/{}'.format(subnet_addr, mask_count)
        # 扫描前检查停止标志（手动终止时不再发起 agent 请求）
        if _is_scan_stopped(subnet.id):
            IpSubnetManagerModel.objects.filter(id=subnet.id).update(
                scan_status='scan_fail', scan_message='手动终止!')
            _scan_cache_set(cache_key, 'true')
            return
        status, res_dict = proxy_api.subnet_mask_scan(subnet_mask_str, timeout)
        if not status:
            IpSubnetManagerModel.objects.filter(id=subnet.id).update(
                scan_status='scan_fail', scan_message=str(res_dict)[:200])
            _scan_cache_set(cache_key, 'true')
            return
        # 扫描完成后若已被手动终止，则不再覆盖 scan_fail 状态
        if _is_scan_stopped(subnet.id):
            _scan_cache_set(cache_key, 'true')
            return

        all_dict = res_dict.get('ip_list_dict', {}) or {}
        up_dict = res_dict.get('ip_dict', {}) or {}
        # 扫描日志（对齐 control：ip_list 全量 + ip 在线 两份）
        log_dict = {'ip_manager_id': subnet.id, 'subnet_addr': subnet_mask_str}
        try:
            IpManagerScanLogModel.objects.create(
                request_id=cache_key, initial_data=json.dumps(all_dict, ensure_ascii=False)[:5000],
                scan_type='ip_list', **log_dict)
        except Exception:
            pass

        fetch_dic = {'ip_manager': subnet}
        ip_total_count, ip_used_count = 0, 0
        all_stats = all_dict.pop('stats', {}) or {}
        all_runtime = all_dict.pop('runtime', {}) or {}
        ip_runtime = up_dict.pop('runtime', {}) or {}
        all_dict.pop('task_results', None)

        new_ip_id_list = []
        for ip, dic in all_dict.items():
            ip_total_count += 1
            fetch_dic['ip_address'] = ip
            ip_query = IpAddressModel.objects.filter(
                ip_manager=subnet, ip_address=ip).first()
            up_ip_dict = up_dict.get(ip)
            if up_ip_dict:
                ip_used_count += 1
                dic = up_ip_dict
            cleaned = _clean_save_ip_dict(dic)
            cleaned['ip_manager'] = subnet
            cleaned['ip_address'] = ip
            if ip_query:
                for k, v in cleaned.items():
                    setattr(ip_query, k, v)
                ip_query.save()
            else:
                ip_query = IpAddressModel.objects.create(**cleaned)
            new_ip_id_list.append(ip_query.id)

        # 删除扫描范围外的历史 IP（对齐 control exclude delete）
        IpAddressModel.objects.filter(ip_manager=subnet).exclude(
            id__in=new_ip_id_list).delete()

        # 时间统计（对齐 control _clean_time）
        elapsed = 0
        try:
            elapsed = float(all_runtime.get('elapsed') or 0) + float(ip_runtime.get('elapsed') or 0)
        except Exception:
            pass
        end_dt = datetime.datetime.now()
        IpSubnetManagerModel.objects.filter(id=subnet.id).update(
            scan_status='scanned',
            scan_message='扫描完成',
            last_scan_time=end_dt,
            ip_total_count=ip_total_count,
            ip_used_count=ip_used_count,
            ip_available_count=ip_total_count - ip_used_count,
            last_scan_end_timestamp=str(int(end_dt.timestamp())),
            last_scan_end_str=end_dt.strftime('%Y-%m-%d %H:%M:%S'),
            elapsed=str(elapsed),
        )
    except Exception as e:
        logger.exception('[ip_scan] %s error: %s', subnet.id, e)
        IpSubnetManagerModel.objects.filter(id=subnet.id).update(
            scan_status='scan_fail', scan_message='扫描异常: {}'.format(str(e)[:200]))
    finally:
        _scan_cache_set(cache_key, 'true')
        _SCAN_THREADS_LOCK.acquire()
        try:
            _SCAN_THREADS.pop('scan_' + str(subnet.id), None)
        finally:
            _SCAN_THREADS_LOCK.release()


def _clean_save_ip_dict(dic):
    """对齐 control SubnetScanComponent._clean_save_ip_dict：状态映射 up→Userd/unknown→Avacliable/else→Notcsan"""
    if not isinstance(dic, dict):
        dic = {}
    scan_state = (dic.get('state') or {}).get('state') if isinstance(dic.get('state'), dict) else None
    macaddress = dic.get('macaddress') or {}
    if scan_state == 'up':
        state = 'Userd'
    elif scan_state == 'unknown':
        state = 'Avacliable'
    else:
        state = 'Notcsan'
    state_obj = dic.get('state') or {}
    return {
        'host_name': dic.get('hostname') or '',
        'ip_type': dic.get('ip_type') or '',
        'mac_address': (macaddress or {}).get('addr') or '',
        'mac_addr_type': (macaddress or {}).get('addrtype') or '',
        'vendor': (macaddress or {}).get('vendor') or '',
        'state': state,
        'state_reason': state_obj.get('reason') if isinstance(state_obj, dict) else '',
        'state_reason_ttl': state_obj.get('reason_ttl') if isinstance(state_obj, dict) else '',
    }


def subnet_mask_scan_view(request):
    """POST /subnet-mask-scan/ — 触发/停止子网扫描 {id, scan_type:"ip"|"ip_stop"}
    对齐 control IpSubnetScan._ip_subnet_scan：
    - ip: 置 scanning → 后台线程扫描（原版是 Celery task）→ cache_key 存状态
    - ip_stop: 终止线程 → 置 scan_fail/手动终止
    """
    if request.method != 'POST':
        return _err('不支持的请求方法')
    try:
        data = json.loads(request.body)
    except Exception:
        return _err('参数错误')
    subnet_id = data.get('id')
    scan_type = data.get('scan_type') or 'ip'
    subnet = IpSubnetManagerModel.objects.filter(id=subnet_id).first()
    if not subnet:
        return _err('子网信息不存在')
    cache_key = 'ip_subnet_scan_{}'.format(subnet.id)

    if scan_type == 'ip':
        if subnet.scan_status == 'scanning':
            return _err('正在扫描，请稍后...')
        _scan_cache_set(cache_key, 'false')
        IpSubnetManagerModel.objects.filter(id=subnet.id).update(
            scan_status='scanning',
            last_scan_time=datetime.datetime.now(),
            scan_message='正在扫描...')
        # 后台线程执行扫描（eSight 无 Celery broker，用线程；语义对齐原版 Celery task）
        t = threading.Thread(target=_run_subnet_scan, args=(subnet, cache_key), daemon=True)
        _SCAN_THREADS_LOCK.acquire()
        try:
            _SCAN_THREADS['scan_' + str(subnet.id)] = t
            # 清除上一次手动终止的停止标志（允许重新扫描）
            _SCAN_STOP_EVENTS.pop(str(subnet.id), None)
        finally:
            _SCAN_THREADS_LOCK.release()
        # ⚠️ 先 start 再 set task 标识会 race：线程秒完成时 set(true) 被 set(thread_scan) 覆盖。
        # task 标识存独立 key（_task 后缀），不污染状态 key（false/true）。
        _scan_cache_set(cache_key + '_task', 'thread_scan_{}'.format(subnet.id))
        t.start()
        return _ok(cache_key, '扫描已触发')
    elif scan_type == 'ip_stop':
        if subnet.scan_status != 'scanning':
            return _err('当前无扫描任务运行！')
        # 终止扫描（对齐原版 celery revoke(terminate=True, SIGTERM)）：
        # 置停止标志 → 线程扫描前/完成后检查到标志则不覆盖状态 → 置 scan_fail/手动终止
        _SCAN_THREADS_LOCK.acquire()
        try:
            ev = _SCAN_STOP_EVENTS.setdefault(str(subnet.id), threading.Event())
            ev.set()
            _SCAN_THREADS.pop('scan_' + str(subnet.id), None)
        finally:
            _SCAN_THREADS_LOCK.release()
        _scan_cache_delete(cache_key)
        _scan_cache_delete(cache_key + '_task')
        IpSubnetManagerModel.objects.filter(id=subnet.id).update(
            scan_status='scan_fail', scan_message='手动终止!')
        return _ok(cache_key, '扫描已停止')
    return _err('参数错误')


def subnet_mask_scan_state_view(request):
    """GET /subnet-mask-scan-state/?cache_key= — 轮询扫描状态
    对齐 control：false=进行中 / task_id=有任务 / true=完成；无 key=数据不存在"""
    cache_key = request.GET.get('cache_key', '')
    data_byte = _scan_cache_get(cache_key)
    if data_byte:
        data_str = str(data_byte)
        if data_str == 'true':
            _scan_cache_delete(cache_key)
        if data_str == 'false':
            data_str = 'false'
        return _ok(data_str)
    return _err('数据不存在')


# ── ip-port-scan/ + ip-port-scan-result/ 端口扫描 ─────────────────
def ip_port_scan_view(request):
    """POST /ip-port-scan/ — 端口扫描（v1 占位）"""
    if request.method != 'POST':
        return _err('不支持的请求方法')
    return _ok({'request_id': ''}, '端口扫描已触发')


def ip_port_scan_result_view(request):
    """GET /ip-port-scan-result/?request_id=&scan_type= — 扫描结果"""
    request_id = request.GET.get('request_id', '')
    scan_type = request.GET.get('scan_type', 'nmap')
    return _ok({'request_id': request_id, 'scan_type': scan_type, 'data': []}, '信息获取成功')
