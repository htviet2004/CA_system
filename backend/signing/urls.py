from django.urls import path
from . import views
from . import upload
from . import history_views

urlpatterns = [
    # PDF Signing
    path('', views.sign_file, name='sign_file'),
    path('upload_p12/', upload.upload_p12, name='upload_p12'),
    path('verify/', views.verify_pdf, name='verify_pdf'),
    path('pdf-info/', views.get_pdf_info, name='pdf_info'),
    
    # Signing History & Document Download
    path('history/', history_views.list_signed_documents, name='signed_documents_list'),
    path('history/stats/', history_views.get_signing_history_stats, name='signing_history_stats'),
    path('history/<int:document_id>/', history_views.get_signed_document_detail, name='signed_document_detail'),
    path('history/<int:document_id>/download/', history_views.download_signed_document, name='download_signed_document'),
    
    # Admin-only Storage Management
    path('storage/stats/', history_views.get_storage_stats, name='storage_stats'),
    path('storage/cleanup/', history_views.run_cleanup, name='storage_cleanup'),
]
