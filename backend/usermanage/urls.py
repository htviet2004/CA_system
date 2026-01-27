from django.urls import path
from . import views
from .profile import update_profile, get_profile
from .auth import get_current_user, logout_view, login_view, register, issue_cert
from .meta import get_roles, get_departments, get_all_meta

urlpatterns = [
    # Authentication
    path('login/', login_view, name='login'),
    path('register/', register, name='register'),
    path('me/', get_current_user, name='current_user'),
    path('logout/', logout_view, name='logout'),
    
    # Certificate management
    path('issue_cert/', issue_cert, name='issue_cert'),
    
    # User dashboard
    path('dashboard/', views.get_user_dashboard, name='user_dashboard'),
    path('change-password/', views.change_password, name='change_password'),
    
    # Meta APIs (public endpoints for form dropdowns)
    path('meta/roles/', get_roles, name='meta_roles'),
    path('meta/departments/', get_departments, name='meta_departments'),
    path('meta/all/', get_all_meta, name='meta_all'),
    
    # User management (admin) - legacy endpoints
    path('list/', views.list_users, name='list_users'),
    path('detail/<str:username>/', views.user_detail, name='user_detail'),
    path('set_active/<str:username>/', views.set_active, name='set_active'),
    path('set_staff/<str:username>/', views.set_staff, name='set_staff'),
    path('reset_password/<str:username>/', views.reset_password, name='reset_password'),
    path('profile/update/', update_profile, name='update_profile'),
    path('profile/<str:username>/', get_profile, name='get_profile'),
    
    # Admin dashboard APIs
    path('admin/stats/', views.admin_stats, name='admin_stats'),
    path('admin/users/', views.admin_users_list, name='admin_users_list'),
    path('admin/users/create/', views.admin_create_user, name='admin_create_user'),
    path('admin/users/<int:user_id>/', views.admin_user_detail, name='admin_user_detail'),
    path('admin/users/<int:user_id>/update/', views.admin_update_user, name='admin_update_user'),
    path('admin/users/<int:user_id>/delete/', views.admin_delete_user, name='admin_delete_user'),
    path('admin/signing-history/', views.admin_signing_history, name='admin_signing_history'),
]
