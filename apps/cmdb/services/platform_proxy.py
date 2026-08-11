# -*- coding: utf-8 -*-
"""
平台管控薄代理 —— eSight 调 OpsAny 管控平台(control) API 的统一入口。

设计原则（用户拍板：完全复刻 control + 薄代理调平台，少维护一套数据）：
  - eSight 的设备/厂商/类型/分组等基础数据**只读平台**，不在 eSight 维护第二套；
  - 本模块转发到 control 的 API 根：BK_URL + /o/control/api/control/v0_1/
  - 认证复用平台会话（bk_token Cookie），eSight 与平台同域，Django 请求自带会话。

已实测接口（2026-08-11）：
  network-equipment-all/     设备列表
  get-network/               从资源平台(CMDB)拉设备
  network-equipment-type-v2/ 厂商品牌 + 设备类型
  network-type/              设备类型 ROUTER/SWITCH/FIREWALL
  network-group/             分组
  network-equipment-test/    连接测试（POST → {snmp_ping, ssh_ping, ...}）
"""
import logging

import requests
from django.conf import settings

logger = logging.getLogger('app')


def get_api_base():
    """平台管控 API 根：默认 BK_URL + /o/control/api/control/v0_1/"""
    base = getattr(settings, 'ESIGHT_PLATFORM_API_BASE', None)
    if base:
        return base.rstrip('/') + '/'
    bk_url = (getattr(settings, 'BK_URL', '') or 'https://192.168.99.31').rstrip('/')
    return f'{bk_url}/o/control/api/control/v0_1/'


def call_api(path, method='GET', params=None, data=None, request=None, timeout=15):
    """
    调平台 control API。

    :param request: Django 请求对象（可选）。提供时复用其会话 Cookie（同域 bk_token），
                    否则尝试从环境/配置读平台会话（用于无请求上下文的任务/脚本）。
    """
    url = get_api_base() + path.lstrip('/')
    headers = {'Content-Type': 'application/json'}

    cookies = None
    if request is not None:
        # 同域部署：eSight 与平台共享 Cookie（bk_token / sessionid），直接透传
        cookies = request.COOKIES or None

    try:
        if method.upper() == 'GET':
            resp = requests.get(url, params=params, headers=headers, cookies=cookies,
                                timeout=timeout, verify=False)
        else:
            resp = requests.request(method.upper(), url, params=params, json=data,
                                    headers=headers, cookies=cookies, timeout=timeout,
                                    verify=False)
        resp.raise_for_status()
    except requests.RequestException as exc:
        logger.error('[platform_proxy] %s %s 失败: %s', method, path, exc)
        raise RuntimeError(f'平台接口调用失败: {exc}')

    try:
        payload = resp.json()
    except ValueError:
        raise RuntimeError(f'平台接口 {path} 返回非 JSON: {resp.text[:200]}')

    # 平台统一信封 {code, successcode, message, data}
    code = payload.get('code')
    if code != 200:
        msg = payload.get('message') or payload.get('msg') or '未知错误'
        logger.warning('[platform_proxy] %s 返回 code=%s: %s', path, code, msg)
        raise RuntimeError(f'平台返回错误({code}): {msg}')
    return payload.get('data')


# ──────────────────────────────────────────────────────────────
# 网络设备
# ──────────────────────────────────────────────────────────────

def get_network_equipments(request=None, **params):
    """设备列表（control 已纳管的设备）"""
    return call_api('network-equipment-all/', params=params or None, request=request)


def add_network_equipment(data, request=None):
    """添加设备（POST network-equipment/）"""
    return call_api('network-equipment/', method='POST', data=data, request=request)


def edit_network_equipment(data, request=None):
    """编辑设备（PUT network-equipment/）"""
    return call_api('network-equipment/', method='PUT', data=data, request=request)


def delete_network_equipment(data, request=None):
    """删除设备（DELETE network-equipment/，data 含 id）"""
    return call_api('network-equipment/', method='DELETE', data=data, request=request)


def flush_network_equipment(request=None, **params):
    """刷新/同步设备（network-equipment-flush/）"""
    return call_api('network-equipment-flush/', params=params or None, request=request)


def get_network_from_cmdb(request=None, **params):
    """从资源平台(CMDB)拉网络设备（"从资源平台添加"）"""
    return call_api('get-network/', params=params or None, request=request)


def test_network_equipment(data, request=None):
    """连接测试：POST {ip, connection_type, snmp_*, ssh_*, ...} → {snmp_ping, ssh_ping, ...}"""
    return call_api('network-equipment-test/', method='POST', data=data, request=request)


def ping_network_equipment(data, request=None):
    """Ping 测试"""
    return call_api('network-equipment-ping/', method='POST', data=data, request=request)


def get_equipment_info(equipment_id, request=None):
    """设备详情"""
    return call_api('network-equipment-info/', params={'id': equipment_id}, request=request)


# ──────────────────────────────────────────────────────────────
# 基础数据（厂商 / 类型 / 分组）
# ──────────────────────────────────────────────────────────────

def get_equipment_type_v2(request=None):
    """厂商品牌 + 设备类型（network-equipment-type-v2）"""
    return call_api('network-equipment-type-v2/', request=request)


def get_network_types(request=None):
    """设备类型列表（ROUTER/SWITCH/FIREWALL）"""
    return call_api('network-type/', request=request)


def get_network_groups(request=None):
    """设备分组"""
    return call_api('network-group/', request=request)


def get_zc_models(request=None):
    """资产模型（get-zc-model）"""
    return call_api('get-zc-model/', request=request)
