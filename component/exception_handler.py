"""
自定义异常处理
"""
import logging
from rest_framework.views import exception_handler
from rest_framework.response import Response

logger = logging.getLogger('esight')


def custom_exception_handler(exc, context):
    """统一异常响应格式"""
    response = exception_handler(exc, context)

    if response is not None:
        response.data = {
            'code': response.status_code,
            'message': response.data.get('detail', str(response.data)) if isinstance(response.data, dict) else str(response.data),
            'data': None,
        }
    else:
        logger.exception(f'Unhandled exception: {exc}')
        response = Response(
            {'code': 500, 'message': '服务器内部错误', 'data': None},
            status=500,
        )
    return response
