# -*- coding: utf-8 -*-
"""
eSight Zabbix 监控数据客户端
============================
2026-08-14 新增：主机监控大屏实时曲线数据源。

背景
----
正式平台（192.168.99.24）内置 Zabbix Server 7.0.3（端口 8006），111 台纳管主机已接入监控。
eSight 通过 Zabbix JSON-RPC API（http://<host>:8006/api_jsonrpc.php）拉取实时/历史指标，
用 ECharts 绘制主机监控大屏曲线。

凭据优先级：环境变量 ZABBIX_URL / ZABBIX_USER / ZABBIX_PASSWORD > 代码内默认值（正式平台开发默认）。
不要修改凭据默认值提交 git（敏感），正式化通过环境变量注入。

已实测（2026-08-14）：
  - apiinfo.version → 7.0.3
  - user.login(zabbixapi) → token
  - host.get countOutput → 106 台（control 111 台，5 台差异：未接监控）
  - item.get → 标准 Linux 模板（system.cpu.util / system.cpu.load / agent.ping / net.if.in/out 等）
  - history.get(itemids, time_from) → 60s 每点真实值
"""
import logging
import os
import threading
import time

import requests

logger = logging.getLogger('app')

ZABBIX_DEFAULT_URL = 'http://192.168.99.24:8006/api_jsonrpc.php'
ZABBIX_DEFAULT_USER = 'zabbixapi'
ZABBIX_DEFAULT_PASSWORD = 'Ops-sand1qaz'

_TOKEN_TTL = 300  # Zabbix token 有效期 5 分钟，到期重登


class ZabbixApi:
    """Zabbix JSON-RPC 客户端（线程安全，token 带过期缓存）"""

    def __init__(self, url='', user='', password='', timeout=15):
        self.url = (url or os.environ.get('ZABBIX_URL') or ZABBIX_DEFAULT_URL).rstrip('/')
        self.user = user or os.environ.get('ZABBIX_USER') or ZABBIX_DEFAULT_USER
        self.password = password or os.environ.get('ZABBIX_PASSWORD') or ZABBIX_DEFAULT_PASSWORD
        self.timeout = timeout
        self._token = None
        self._token_at = 0
        self._lock = threading.Lock()

    # ── 底层调用 ─────────────────────────────────────────────
    def _call(self, method, params, auth=False):
        body = {'jsonrpc': '2.0', 'method': method, 'params': params, 'id': 1}
        if auth:
            body['auth'] = self._get_token()
        try:
            r = requests.post(self.url, json=body, timeout=self.timeout, verify=False)
            r.raise_for_status()
            data = r.json()
        except Exception as e:
            logger.error('[zabbix] %s call error: %s', method, e)
            return None
        if 'error' in data:
            err = data['error']
            logger.error('[zabbix] %s error: %s', method, err.get('data', err))
            # token 失效 → 强制重登重试一次
            if auth and err.get('code') in (-32602, -32700):
                with self._lock:
                    self._token = None
                return self._call(method, params, auth)
            return None
        return data.get('result')

    def _get_token(self):
        with self._lock:
            if self._token and time.time() - self._token_at < _TOKEN_TTL:
                return self._token
            result = self._call('user.login', {'username': self.user, 'password': self.password})
            if result:
                self._token = result
                self._token_at = time.time()
                return self._token
            return ''

    # ── 业务封装 ─────────────────────────────────────────────
    def api_version(self):
        return self._call('apiinfo.version', {})

    def host_get(self, host_ip=None, limit=None, count_output=False):
        """按 host 名（IP）查主机。返回 list[dict] 或 int（count）"""
        params = {'output': ['hostid', 'host', 'name', 'status']}
        if host_ip:
            params['filter'] = {'host': [host_ip]}
        if count_output:
            params['countOutput'] = True
        if limit:
            params['limit'] = limit
        return self._call('host.get', params, auth=True)

    def item_get(self, host_id, key_search=None, limit=None):
        """查主机的监控项。key_search 支持 list（子串匹配）。host_id 支持 str 或 list（批量）。
        返回 list[dict]"""
        params = {
            'output': ['itemid', 'name', 'key_', 'units', 'value_type', 'lastvalue', 'lastclock', 'hostid'],
        }
        if isinstance(host_id, (list, tuple)):
            params['hostids'] = [str(h) for h in host_id]
        else:
            params['hostids'] = host_id
        if key_search:
            params['search'] = {'key_': key_search}
            params['searchWildcardsEnabled'] = True
        if limit:
            params['limit'] = limit
        return self._call('item.get', params, auth=True)

    def history_get(self, item_ids, time_from=None, time_till=None, limit=1000, history=None):
        """历史数据（1h/6h/24h 用）。item_ids 支持 list 或 str。
        history 类型：0=float,1=char,2=log,3=uint,4=text；默认自动（value_type 映射在调用方）"""
        if isinstance(item_ids, (list, tuple)):
            item_ids = [str(i) for i in item_ids]
        params = {
            'itemids': item_ids,
            'sortfield': 'clock',
            'sortorder': 'ASC',
            'limit': limit,
        }
        if time_from:
            params['time_from'] = int(time_from)
        if time_till:
            params['time_till'] = int(time_till)
        if history is not None:
            params['history'] = history
        return self._call('history.get', params, auth=True)

    def trend_get(self, item_ids, time_from=None, time_till=None, limit=1000):
        """趋势数据（7d 等大时间范围用，Zabbix 每小时聚合）"""
        if isinstance(item_ids, (list, tuple)):
            item_ids = [str(i) for i in item_ids]
        params = {
            'itemids': item_ids,
            'sortfield': 'clock',
            'sortorder': 'ASC',
            'limit': limit,
        }
        if time_from:
            params['time_from'] = int(time_from)
        if time_till:
            params['time_till'] = int(time_till)
        return self._call('trend.get', params, auth=True)

    def trigger_get(self, only_problems=True, host_ids=None, limit=500):
        """当前告警（未解决 trigger）。host_ids 支持 list/str
        ⚠️ 2026-08-17：关联主机用 selectHosts（不是 output 里的 hosts——Zabbix API 里 output 无效），
        否则告警列表拿不到主机名/IP（前端显示"-"）。"""
        params = {
            'output': ['triggerid', 'description', 'priority', 'value', 'lastchange'],
            'selectHosts': ['hostid', 'host', 'name'],
            'only_true': True,
        }
        if only_problems:
            params['filter'] = {'value': 1}  # 1=PROBLEM
        if host_ids:
            params['hostids'] = host_ids
        if limit:
            params['limit'] = limit
        return self._call('trigger.get', params, auth=True)

    def event_get(self, source=3, value=None, time_from=None, time_till=None,
                  host_ids=None, limit=500, object_ids=None):
        """告警事件（source=3 trigger 事件）。value: 1=PROBLEM, 0=RESOLVED"""
        params = {
            'output': ['eventid', 'clock', 'value', 'acknowledged', 'objectid', 'name'],
            'source': source,
            'sortfield': 'clock',
            'sortorder': 'DESC',
            'limit': limit,
        }
        if value is not None:
            params['value'] = value
        if time_from:
            params['time_from'] = int(time_from)
        if time_till:
            params['time_till'] = int(time_till)
        if host_ids:
            params['hostids'] = host_ids
        if object_ids:
            params['objectids'] = object_ids
        return self._call('event.get', params, auth=True)


# 模块级单例（token 缓存共享）
_zabbix_singleton = None
_zabbix_lock = threading.Lock()


def get_zabbix_api():
    global _zabbix_singleton
    if _zabbix_singleton is None:
        with _zabbix_lock:
            if _zabbix_singleton is None:
                _zabbix_singleton = ZabbixApi()
    return _zabbix_singleton
