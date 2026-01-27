from django.db import models
from django.contrib.auth.models import User
import hashlib


class UserCert(models.Model):
    """
    User Certificate Model
    Stores encrypted PKCS#12 certificates for users.
    
    Fields:
        - user: Foreign key to Django User
        - common_name: Certificate CN (usually username)
        - serial_number: Certificate serial number (for CRL integration)
        - p12_enc_path: Path to encrypted P12 file
        - p12_pass_enc_path: Path to encrypted passphrase file
        - created_at: Certificate creation timestamp
        - valid_from: Certificate validity start date
        - expires_at: Certificate expiration date
        - active: Whether certificate is active (not revoked)
        - revoked_at: Timestamp of revocation (if revoked)
        - revocation_reason: Reason for revocation
    """
    
    REVOCATION_REASONS = [
        ('unspecified', 'Unspecified'),
        ('key_compromise', 'Key Compromise'),
        ('ca_compromise', 'CA Compromise'),
        ('affiliation_changed', 'Affiliation Changed'),
        ('superseded', 'Superseded'),
        ('cessation_of_operation', 'Cessation of Operation'),
        ('certificate_hold', 'Certificate Hold'),
        ('privilege_withdrawn', 'Privilege Withdrawn'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='certificates')
    common_name = models.CharField(max_length=200, blank=True)
    serial_number = models.CharField(max_length=64, blank=True, db_index=True)
    p12_enc_path = models.CharField(max_length=1024)
    p12_pass_enc_path = models.CharField(max_length=1024)
    created_at = models.DateTimeField(auto_now_add=True)
    valid_from = models.DateTimeField(null=True, blank=True, help_text="Certificate validity start date")
    expires_at = models.DateTimeField(null=True, blank=True, help_text="Certificate expiration date")
    active = models.BooleanField(default=True, db_index=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revocation_reason = models.CharField(
        max_length=32, 
        choices=REVOCATION_REASONS, 
        blank=True
    )
    revoked_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='revoked_certs'
    )

    class Meta:
        indexes = [
            models.Index(fields=['user', 'active']),
            models.Index(fields=['serial_number']),
        ]

    def __str__(self):
        status = "REVOKED" if not self.active else "ACTIVE"
        return f"{self.user.username} - {self.common_name or 'cert'} [{status}]"
    
    def revoke(self, reason='unspecified', revoked_by=None):
        """Revoke this certificate."""
        from django.utils import timezone
        self.active = False
        self.revoked_at = timezone.now()
        self.revocation_reason = reason
        self.revoked_by = revoked_by
        self.save()
        
        # Also mark all signatures using this cert as revoked
        SigningHistory.objects.filter(
            certificate=self,
            status='valid'
        ).update(
            status='revoked',
            updated_at=timezone.now()
        )


class SigningHistory(models.Model):
    """
    Digital Signing History Model
    Records every PDF signing action for audit trail and file storage.
    
    Fields:
        - user: User who performed the signing
        - certificate: Certificate used for signing
        - document_name: Original filename
        - document_hash: SHA-256 hash of signed document
        - document_size: File size in bytes
        - signed_at: Timestamp of signing
        - expires_at: When the stored file expires and can be deleted
        - reason: Signing reason/purpose
        - location: Signing location (deprecated)
        - status: Current status (valid/revoked/expired/deleted)
        - file_path: Path to stored signed PDF (relative to SIGNED_PDF_STORAGE_DIR)
        - download_count: Number of times the file has been downloaded
        - ip_address: IP address of signer
    
    File Storage:
        - Signed PDFs are stored for a configurable retention period
        - Files are stored in SIGNED_PDF_STORAGE_DIR/{year}/{month}/{user_id}/
        - After expires_at, files can be cleaned up by scheduled task
    
    Immutability:
        - Records are append-only (no updates except status/download_count)
        - Hash ensures document integrity verification
    """
    
    STATUS_CHOICES = [
        ('valid', 'Valid'),
        ('revoked', 'Revoked'),
        ('expired', 'Expired'),
        ('invalid', 'Invalid'),
        ('deleted', 'Deleted'),  # File has been cleaned up
    ]
    
    user = models.ForeignKey(
        User, 
        on_delete=models.PROTECT,  # Prevent user deletion if signing history exists
        related_name='signing_history'
    )
    certificate = models.ForeignKey(
        UserCert, 
        on_delete=models.PROTECT,  # Prevent cert deletion if used for signing
        related_name='signing_history',
        null=True
    )
    
    # Document identification
    document_name = models.CharField(max_length=512)
    document_hash = models.CharField(max_length=64, db_index=True)  # SHA-256
    document_size = models.BigIntegerField(default=0)
    
    # File storage - NEW FIELDS
    file_path = models.CharField(
        max_length=1024, 
        blank=True,
        help_text="Relative path to signed PDF in SIGNED_PDF_STORAGE_DIR"
    )
    download_count = models.PositiveIntegerField(default=0)
    last_downloaded_at = models.DateTimeField(null=True, blank=True)
    
    # Signing metadata
    signed_at = models.DateTimeField(auto_now_add=True, db_index=True)
    expires_at = models.DateTimeField(
        null=True, 
        blank=True, 
        db_index=True,
        help_text="When the stored file expires and can be deleted"
    )
    reason = models.CharField(max_length=512, blank=True)
    location = models.CharField(max_length=256, blank=True)  # Deprecated
    
    # Status and audit
    status = models.CharField(
        max_length=16, 
        choices=STATUS_CHOICES, 
        default='valid',
        db_index=True
    )
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=512, blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Revocation fields
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='revoked_signatures'
    )
    revocation_reason = models.CharField(max_length=256, blank=True)

    class Meta:
        ordering = ['-signed_at']
        indexes = [
            models.Index(fields=['user', 'signed_at']),
            models.Index(fields=['document_hash']),
            models.Index(fields=['status']),
            models.Index(fields=['expires_at']),  # For cleanup queries
        ]
        verbose_name_plural = 'Signing histories'

    def __str__(self):
        return f"{self.user.username} signed {self.document_name} at {self.signed_at}"
    
    @staticmethod
    def compute_hash(file_content):
        """Compute SHA-256 hash of document content."""
        return hashlib.sha256(file_content).hexdigest()
    
    def revoke(self, reason='', revoked_by=None):
        """Revoke this specific signature."""
        from django.utils import timezone
        self.status = 'revoked'
        self.revoked_at = timezone.now()
        self.revoked_by = revoked_by
        self.revocation_reason = reason
        self.save()
    
    def is_expired(self):
        """Check if the stored file has expired."""
        from django.utils import timezone
        if not self.expires_at:
            return False
        return timezone.now() > self.expires_at
    
    def is_downloadable(self):
        """Check if the file can be downloaded."""
        return (
            self.file_path and 
            self.status in ('valid', 'revoked') and 
            not self.is_expired()
        )
    
    def get_full_file_path(self):
        """Get the full filesystem path to the stored file."""
        from django.conf import settings
        if not self.file_path:
            return None
        return settings.SIGNED_PDF_STORAGE_DIR / self.file_path
    
    def increment_download(self):
        """Increment download counter and update last downloaded timestamp."""
        from django.utils import timezone
        self.download_count += 1
        self.last_downloaded_at = timezone.now()
        self.save(update_fields=['download_count', 'last_downloaded_at', 'updated_at'])
    
    def mark_deleted(self):
        """Mark the file as deleted (after cleanup)."""
        self.status = 'deleted'
        self.file_path = ''
        self.save(update_fields=['status', 'file_path', 'updated_at'])


class CertificateRevocationLog(models.Model):
    """
    Certificate Revocation Log (CRL integration)
    Maintains audit trail of all revocation actions.
    """
    
    certificate = models.ForeignKey(
        UserCert, 
        on_delete=models.CASCADE,
        related_name='revocation_logs'
    )
    revoked_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    revoked_at = models.DateTimeField(auto_now_add=True)
    reason = models.CharField(max_length=32)
    notes = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-revoked_at']

    def __str__(self):
        return f"Revoked {self.certificate} at {self.revoked_at}"


class SecurityAuditLog(models.Model):
    """
    Security Audit Log for tracking all security-relevant events.
    
    SECURITY: This is an append-only log. Records should never be modified or deleted.
    Use this for compliance auditing, security incident investigation, and monitoring.
    
    Event Categories:
    - AUTH: Authentication events (login, logout, failed attempts)
    - CERT: Certificate operations (issue, revoke, upload)
    - SIGN: Document signing operations
    - ADMIN: Administrative actions (user management, permission changes)
    - ACCESS: Access control events (forbidden access attempts)
    - CONFIG: Configuration changes
    """
    
    CATEGORY_CHOICES = [
        ('AUTH', 'Authentication'),
        ('CERT', 'Certificate'),
        ('SIGN', 'Signing'),
        ('ADMIN', 'Administration'),
        ('ACCESS', 'Access Control'),
        ('CONFIG', 'Configuration'),
    ]
    
    SEVERITY_CHOICES = [
        ('DEBUG', 'Debug'),
        ('INFO', 'Info'),
        ('WARNING', 'Warning'),
        ('ERROR', 'Error'),
        ('CRITICAL', 'Critical'),
    ]
    
    # Event identification
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    category = models.CharField(max_length=16, choices=CATEGORY_CHOICES, db_index=True)
    action = models.CharField(max_length=64, db_index=True)
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES, default='INFO')
    
    # Actor information
    user = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='audit_logs'
    )
    username = models.CharField(max_length=150, blank=True, db_index=True)  # Preserved even if user deleted
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=512, blank=True)
    
    # Event details
    target_type = models.CharField(max_length=64, blank=True)  # e.g., 'User', 'Certificate', 'Document'
    target_id = models.CharField(max_length=128, blank=True)  # ID of the target object
    description = models.TextField(blank=True)
    
    # Outcome
    success = models.BooleanField(default=True)
    error_message = models.TextField(blank=True)
    
    # Additional context (JSON-encoded)
    extra_data = models.JSONField(default=dict, blank=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['timestamp']),
            models.Index(fields=['category', 'action']),
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['username', 'timestamp']),
            models.Index(fields=['ip_address']),
            models.Index(fields=['success', 'category']),
        ]
        # SECURITY: Prevent accidental deletion of audit records
        permissions = [
            ('view_audit_logs', 'Can view security audit logs'),
            ('export_audit_logs', 'Can export security audit logs'),
        ]

    def __str__(self):
        return f"[{self.timestamp}] {self.category}/{self.action} by {self.username or 'anonymous'}"
    
    @classmethod
    def log(cls, category, action, request=None, user=None, success=True, 
            severity='INFO', target_type='', target_id='', description='',
            error_message='', extra_data=None):
        """
        Create an audit log entry.
        
        Args:
            category: Event category (AUTH, CERT, SIGN, ADMIN, ACCESS, CONFIG)
            action: Specific action (e.g., 'LOGIN', 'LOGOUT', 'ISSUE_CERT')
            request: Django request object (optional, for IP/user agent)
            user: User object (optional, falls back to request.user)
            success: Whether the action succeeded
            severity: Log severity (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            target_type: Type of object affected
            target_id: ID of object affected
            description: Human-readable description
            error_message: Error details if success=False
            extra_data: Additional JSON-serializable data
        """
        username = ''
        ip_address = None
        user_agent = ''
        
        if request:
            # Get user from request if not provided
            if user is None and hasattr(request, 'user') and request.user.is_authenticated:
                user = request.user
            
            # Get IP address
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                ip_address = x_forwarded_for.split(',')[0].strip()
            else:
                ip_address = request.META.get('REMOTE_ADDR')
            
            # Get user agent
            user_agent = request.META.get('HTTP_USER_AGENT', '')[:512]
        
        if user:
            username = user.username
        
        return cls.objects.create(
            category=category,
            action=action,
            severity=severity,
            user=user,
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            target_type=target_type,
            target_id=str(target_id) if target_id else '',
            description=description,
            success=success,
            error_message=error_message,
            extra_data=extra_data or {},
        )

