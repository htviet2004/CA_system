from django.urls import path
from . import views
from . import upload

urlpatterns = [
    path('', views.sign_file, name='sign_file'),
    path('upload_p12/', upload.upload_p12, name='upload_p12'),
    path('verify/', views.verify_pdf, name='verify_pdf'),
    path('pdf-info/', views.get_pdf_info, name='pdf_info'), 
]
