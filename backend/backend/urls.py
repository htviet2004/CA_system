from django.contrib import admin
from django.urls import path, include
from django.views.generic import TemplateView
from django.conf import settings
from django.http import FileResponse, HttpResponseRedirect
from django.urls import re_path
import os

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/sign/', include('signing.urls')),
    path('api/usercerts/', include('usercerts.urls')),
    path('api/usermanage/', include('usermanage.urls')),
]


def serve_react(request, path=''):
    base = settings.BASE_DIR
    # Prefer CRA build then Vite dist
    build_index = os.path.normpath(os.path.join(base, '..', 'frontend', 'build', 'index.html'))
    dist_index = os.path.normpath(os.path.join(base, '..', 'frontend', 'dist', 'index.html'))
    if os.path.exists(build_index):
        return FileResponse(open(build_index, 'rb'), content_type='text/html')
    if os.path.exists(dist_index):
        return FileResponse(open(dist_index, 'rb'), content_type='text/html')
    # fallback to dev server
    return HttpResponseRedirect('http://localhost:3000' + request.path)


# catch-all for client-side routes
urlpatterns += [
    re_path(r'^(?:.*)/?$', serve_react),
]
