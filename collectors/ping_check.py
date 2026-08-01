"""
Ping 存活检测
"""
import subprocess
import platform
import logging

logger = logging.getLogger('esight.collector.ping')


def ping_check(ip_address, timeout=3, count=1):
    """
    Ping 检测主机是否存活
    返回: True/False
    """
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'

    try:
        result = subprocess.run(
            ['ping', param, str(count), timeout_param, str(timeout), ip_address],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 2,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, Exception) as e:
        logger.debug(f'Ping 失败: {ip_address} - {e}')
        return False


def ping_latency(ip_address, count=3):
    """
    Ping 测量延迟
    返回: {'min': ms, 'avg': ms, 'max': ms, 'loss': %} or None
    """
    try:
        result = subprocess.run(
            ['ping', '-c', str(count), '-W', '3', ip_address],
            capture_output=True, text=True,
            timeout=count * 3 + 5,
        )
        output = result.stdout

        # 解析 rtt
        rtt_match = None
        import re
        rtt_match = re.search(r'rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)', output)
        if rtt_match:
            return {
                'min': float(rtt_match.group(1)),
                'avg': float(rtt_match.group(2)),
                'max': float(rtt_match.group(3)),
                'loss': _parse_loss(output),
            }
        return None
    except Exception as e:
        logger.debug(f'Ping 延迟测量失败: {ip_address} - {e}')
        return None


def _parse_loss(output):
    """解析丢包率"""
    import re
    match = re.search(r'(\d+)% packet loss', output)
    return float(match.group(1)) if match else 100.0
