# -*- coding: utf-8 -*-
"""
假 ESB SDK（shim）。

OpsAny 平台的 blueapps 登录流程（TokenBackend）会调用 ESB SDK（blueking.component）
校验 bk_token（client.bk_login.is_login）并获取用户信息（client.bk_login.get_user）。
但 blueking.component 不在公共 PyPI，平台 venv 也不预装；缺失时 blueapps 走
DummyClient 抛 ModuleNotFoundError，登录必然失败。

本 shim 通过 settings.ESB_SDK_NAME 接管 SDK 调用：
- ``is_login`` 抛 NotImplementedError —— 触发 blueapps 内置 fallback 到
  ``verify_bk_token_through_verify_url``（直接 HTTP 调平台登录 /accounts/is_login/ 校验 token，无需 ESB）；
- ``get_user`` 直接 HTTP 调平台登录 /accounts/get_user/ 获取用户信息。
"""
import requests

from blueapps.account.conf import ConfFixture


class _BkLogin(object):
    """模拟 ``client.bk_login`` 模块。"""

    def is_login(self, api_params):
        raise NotImplementedError("ESB SDK 未安装，自动走 verify_url 通道")

    def get_user(self, api_params):
        url = ConfFixture.USER_INFO_URL
        return requests.get(url, params=api_params, verify=False, timeout=10).json()


class ComponentClient(object):
    """模拟 SDK 的 ComponentClient（get_client_by_request / get_client_by_user 返回）。"""

    def __init__(self, *args, **kwargs):
        self.common_args = kwargs

    @property
    def bk_login(self):
        return _BkLogin()
