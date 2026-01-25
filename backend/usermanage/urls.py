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
    
    # User management (admin)
    path('list/', views.list_users, name='list_users'),
    path('detail/<str:username>/', views.user_detail, name='user_detail'),
    path('set_active/<str:username>/', views.set_active, name='set_active'),
    path('set_staff/<str:username>/', views.set_staff, name='set_staff'),
    path('reset_password/<str:username>/', views.reset_password, name='reset_password'),
    path('profile/update/', update_profile, name='update_profile'),
    path('profile/<str:username>/', get_profile, name='get_profile'),
]
