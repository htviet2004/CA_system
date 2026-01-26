from django.urls import path
from . import views
from . import upload
from usermanage import auth

urlpatterns = [
    path('', views.sign_file, name='sign_file'),
    path('upload_p12/', upload.upload_p12, name='upload_p12'),
    path('register/', auth.register, name='register'),
    path('login/', auth.login_view, name='login'),
    path('issue_cert/', auth.issue_cert, name='issue_cert'),
    path('verify/', views.verify_pdf, name='verify_pdf'),
    path('pdf-info/', views.get_pdf_info, name='pdf_info'),
    path('cached-pdf/', views.get_cached_pdf, name='get_cached_pdf'),
    path('check-cache/', views.check_cached_pdf, name='check_cached_pdf'),
    path('clear-cache/', views.clear_cached_pdf, name='clear_cached_pdf'),
    path('verify-cache-status/', views.verify_cache_status, name='verify_cache_status'),
    path('signed-pdfs-log/', views.get_signed_pdfs_log, name='get_signed_pdfs_log'),
]
