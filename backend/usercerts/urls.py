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
]
