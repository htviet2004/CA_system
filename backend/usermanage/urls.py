from django.urls import path
from . import views
from .profile import update_profile, get_profile

urlpatterns = [
    path('list/', views.list_users, name='list_users'),
    path('detail/<str:username>/', views.user_detail, name='user_detail'),
    path('set_active/<str:username>/', views.set_active, name='set_active'),
    path('set_staff/<str:username>/', views.set_staff, name='set_staff'),
    path('reset_password/<str:username>/', views.reset_password, name='reset_password'),
    path('profile/update/', update_profile, name='update_profile'),
    path('profile/<str:username>/', get_profile, name='get_profile'),
]
