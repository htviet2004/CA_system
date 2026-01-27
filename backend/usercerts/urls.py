from django.urls import path
from . import views

urlpatterns = [
    # Certificate management
    path('list/', views.list_certs, name='list_certs'),
    path('issue/', views.issue_cert, name='issue_cert'),
    path('upload/', views.upload_p12, name='upload_p12'),
    path('download/<int:pk>/', views.download_p12, name='download_p12'),
    path('revoke/<int:pk>/', views.revoke_cert, name='revoke_cert'),
    
    # Signing history APIs
    path('history/', views.list_signing_history, name='signing_history_list'),
    path('history/user/<str:username>/', views.signing_history_by_user, name='signing_history_by_user'),
    path('history/document/<str:doc_hash>/', views.signing_history_by_document, name='signing_history_by_document'),
    path('history/<int:pk>/revoke/', views.revoke_signature, name='revoke_signature'),
    
    # Revocation management (admin only)
    path('revocation/log/', views.revocation_log, name='revocation_log'),
    path('revocation/check/<str:serial_or_hash>/', views.check_revocation_status, name='check_revocation'),
    
    # User dashboard APIs
    path('certificate-info/', views.get_certificate_info, name='certificate_info'),
    path('signing-stats/', views.get_signing_stats, name='signing_stats'),
    path('download/', views.download_certificate, name='download_certificate'),
    path('renew/', views.renew_certificate, name='renew_certificate'),
    
    # Admin-only certificate management
    path('admin/reissue/<int:user_id>/', views.admin_reissue_certificate, name='admin_reissue_certificate'),
    path('admin/force-renew/<int:cert_id>/', views.admin_force_renew, name='admin_force_renew'),
    path('admin/all-certificates/', views.admin_list_all_certificates, name='admin_list_all_certificates'),
]
