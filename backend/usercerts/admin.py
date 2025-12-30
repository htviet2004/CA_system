from django.contrib import admin
from .models import UserCert


@admin.register(UserCert)
class UserCertAdmin(admin.ModelAdmin):
    list_display = ('user', 'common_name', 'created_at', 'active')
    search_fields = ('user__username', 'common_name')
