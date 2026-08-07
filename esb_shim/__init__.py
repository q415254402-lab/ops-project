# -*- coding: utf-8 -*-
"""假 ESB SDK shim —— 供 blueapps esbclient 导入（settings.ESB_SDK_NAME='esb_shim'）。"""

from . import client, shortcuts  # noqa: F401
from .base import ComponentAPI  # noqa: F401
