"""SPA 入口视图：渲染前端构建产物 templates/index.html"""
from django.views.generic import TemplateView


class IndexView(TemplateView):
    template_name = 'index.html'

    def get_context_data(self, **kwargs):
        """⚠️ 2026-08-14 修复：control dist 模板里 window.API_ROOT = "{{SITE_URL}}"，必须传 SITE_URL，
        否则 API_ROOT 为空 → axios baseURL 拼出 'undefined/...' → 前端拿不到数据。
        SITE_URL = 应用前缀（/t/esight/ 或 /o/esight/），由 StripSitePrefixMiddleware 写入 SCRIPT_NAME。
        """
        ctx = super().get_context_data(**kwargs)
        script = getattr(self.request, 'META', {}).get('SCRIPT_NAME') or ''
        ctx['SITE_URL'] = (script or '') + '/'
        return ctx
