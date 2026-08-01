"""SPA 入口视图：渲染前端构建产物 templates/index.html"""
from django.views.generic import TemplateView


class IndexView(TemplateView):
    template_name = 'index.html'
