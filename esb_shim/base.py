# -*- coding: utf-8 -*-
"""esbclient 需要的 base.ComponentAPI（patch_sdk_component_api_class 会引用它）。"""


class ComponentAPI(object):
    allowed_methods = ["GET", "POST"]

    def __init__(self, *args, **kwargs):
        pass
