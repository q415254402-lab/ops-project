# -*- coding: utf-8 -*-
"""esbclient 的 shortcuts（get_client_by_request / get_client_by_user）。"""

from .client import ComponentClient


def get_client_by_request(request=None):
    return ComponentClient()


def get_client_by_user(username):
    return ComponentClient()
