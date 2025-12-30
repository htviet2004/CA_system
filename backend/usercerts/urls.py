from django.urls import path
from . import views

urlpatterns = [
    path('list/', views.list_certs, name='list_certs'),
    path('issue/', views.issue_cert, name='issue_cert'),
    path('upload/', views.upload_p12, name='upload_p12'),
    path('download/<int:pk>/', views.download_p12, name='download_p12'),
    path('revoke/<int:pk>/', views.revoke_cert, name='revoke_cert'),
]
