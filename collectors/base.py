"""
采集器基类
"""
import logging
from abc import ABC, abstractmethod

logger = logging.getLogger('esight.collector')


class BaseCollector(ABC):
    """设备采集器基类"""

    def __init__(self, ip_address, credential=None, timeout=10, retries=3):
        self.ip_address = ip_address
        self.credential = credential
        self.timeout = timeout
        self.retries = retries
        self._connected = False

    @abstractmethod
    def connect(self):
        """建立连接"""
        pass

    @abstractmethod
    def disconnect(self):
        """断开连接"""
        pass

    @abstractmethod
    def get_system_info(self):
        """获取设备基本信息"""
        pass

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()
        return False

    def _safe_float(self, value, default=0.0):
        """安全转换为 float"""
        try:
            return float(value)
        except (ValueError, TypeError):
            return default

    def _safe_int(self, value, default=0):
        """安全转换为 int"""
        try:
            return int(value)
        except (ValueError, TypeError):
            return default
