from django.contrib import admin
from django.urls import path, include
from django.views.generic import TemplateView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', TemplateView.as_view(template_name='index.html'), name='home'),
    path('signing/', TemplateView.as_view(template_name='signing.html'), name='signing'),
    path('api/sign/', include('signing.urls')),
    path('api/usercerts/', include('usercerts.urls')),
    path('api/usermanage/', include('usermanage.urls')),
]
