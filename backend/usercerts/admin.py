from django.contrib import admin
from .models import UserCert, SigningHistory, CertificateRevocationLog


@admin.register(UserCert)
class UserCertAdmin(admin.ModelAdmin):
    list_display = ('user', 'common_name', 'serial_number', 'created_at', 'expires_at', 'active', 'revoked_at')
    list_filter = ('active', 'revocation_reason', 'created_at')
    search_fields = ('user__username', 'common_name', 'serial_number')
    readonly_fields = ('created_at', 'revoked_at', 'revoked_by')
    
    fieldsets = (
        ('Certificate Info', {
            'fields': ('user', 'common_name', 'serial_number', 'p12_enc_path', 'p12_pass_enc_path')
        }),
        ('Validity', {
            'fields': ('active', 'created_at', 'expires_at')
        }),
        ('Revocation', {
            'fields': ('revoked_at', 'revocation_reason', 'revoked_by'),
            'classes': ('collapse',)
        }),
    )


@admin.register(SigningHistory)
class SigningHistoryAdmin(admin.ModelAdmin):
    list_display = ('user', 'document_name', 'signed_at', 'status', 'certificate')
    list_filter = ('status', 'signed_at')
    search_fields = ('user__username', 'document_name', 'document_hash')
    readonly_fields = ('created_at', 'updated_at', 'signed_at', 'document_hash', 'ip_address')
    date_hierarchy = 'signed_at'
    
    fieldsets = (
        ('Document', {
            'fields': ('document_name', 'document_hash', 'document_size')
        }),
        ('Signing Info', {
            'fields': ('user', 'certificate', 'signed_at', 'reason', 'location')
        }),
        ('Status', {
            'fields': ('status', 'revoked_at', 'revoked_by', 'revocation_reason')
        }),
        ('Audit', {
            'fields': ('ip_address', 'user_agent', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(CertificateRevocationLog)
class CertificateRevocationLogAdmin(admin.ModelAdmin):
    list_display = ('certificate', 'revoked_by', 'revoked_at', 'reason')
    list_filter = ('reason', 'revoked_at')
    search_fields = ('certificate__common_name', 'revoked_by__username', 'notes')
    readonly_fields = ('revoked_at',)

