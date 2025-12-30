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
    path('verify/', auth.verify, name='verify'),
]
