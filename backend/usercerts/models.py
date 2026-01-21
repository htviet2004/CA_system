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
    expires_at = models.DateTimeField(null=True, blank=True)
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
    Records every PDF signing action for audit trail.
    
    Fields:
        - user: User who performed the signing
        - certificate: Certificate used for signing
        - document_name: Original filename
        - document_hash: SHA-256 hash of signed document
        - document_size: File size in bytes
        - signed_at: Timestamp of signing
        - reason: Signing reason/purpose
        - location: Signing location
        - status: Current status (valid/revoked/expired)
        - ip_address: IP address of signer
    
    Immutability:
        - Records are append-only (no updates except status)
        - Hash ensures document integrity verification
    """
    
    STATUS_CHOICES = [
        ('valid', 'Valid'),
        ('revoked', 'Revoked'),
        ('expired', 'Expired'),
        ('invalid', 'Invalid'),
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
    
    # Signing metadata
    signed_at = models.DateTimeField(auto_now_add=True, db_index=True)
    reason = models.CharField(max_length=512, blank=True)
    location = models.CharField(max_length=256, blank=True)
    
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

