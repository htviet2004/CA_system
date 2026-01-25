from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class UserProfile(models.Model):
    """
    Extended user profile for PKI system.
    
    Fields affecting certificate subject (CN):
        - full_name: Used in certificate Common Name if provided
        - email: May be included in certificate Subject Alternative Name
    
    Informational fields (do NOT affect certificate):
        - phone: Contact information only
        - department: Organizational unit (informational)
        - role: Access control and authorization only
        - notes: Free-form notes
    
    SECURITY: Role changes are logged for audit purposes.
    Profile changes do NOT automatically invalidate existing certificates.
    """
    
    # Role choices - consistent between frontend and backend
    ROLE_CHOICES = [
        ('student', 'Student'),
        ('lecturer', 'Lecturer'),
        ('staff', 'Staff'),
        ('admin', 'Administrator'),
    ]
    
    # Department/Faculty choices - extensible via admin or future DB table
    DEPARTMENT_CHOICES = [
        ('cntt', 'Khoa Công nghệ Thông tin'),
        ('dien', 'Khoa Điện'),
        ('dtvt', 'Khoa Điện tử - Viễn thông'),
        ('cokhi', 'Khoa Cơ khí'),
        ('ckgt', 'Khoa Cơ khí Giao thông'),
        ('nhiet', 'Khoa Công nghệ Nhiệt - Điện lạnh'),
        ('hoa', 'Khoa Công nghệ Hóa học'),
        ('xddd', 'Khoa Xây dựng Dân dụng và Công nghiệp'),
        ('xdcd', 'Khoa Xây dựng Cầu đường'),
        ('xdtl', 'Khoa Xây dựng Thủy lợi - Thủy điện'),
        ('kientruc', 'Khoa Kiến trúc'),
        ('moitruong', 'Khoa Môi trường'),
        ('qlda', 'Khoa Quản lý Dự án'),
        ('fast', 'Khoa Khoa học Công nghệ Tiên tiến (FAST)'),
        ('khcb', 'Khoa Khoa học Cơ bản'), # Thường dùng cho giảng viên hoặc các môn đại cương
        ('other', 'Khác'),
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    
    # Identity fields (may affect certificate subject)
    full_name = models.CharField(max_length=128, blank=True, help_text="Full name - may be used in certificate CN")
    email = models.EmailField(blank=True, help_text="Email - may be included in certificate SAN")
    
    # Contact information (informational only)
    phone = models.CharField(max_length=32, blank=True, help_text="Phone number with optional country code")
    
    # Organization fields (informational only)
    department = models.CharField(
        max_length=32, 
        blank=True, 
        choices=DEPARTMENT_CHOICES,
        help_text="Department/Faculty"
    )
    role = models.CharField(
        max_length=32, 
        blank=True,
        choices=ROLE_CHOICES,
        default='student',
        help_text="User role for access control"
    )
    
    # Optional notes
    notes = models.TextField(blank=True, max_length=500, help_text="Optional notes or description")
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'User Profile'
        verbose_name_plural = 'User Profiles'
    
    def __str__(self):
        return f"Profile: {self.user.username} ({self.get_role_display()})"
    
    @classmethod
    def get_role_choices_list(cls):
        """Return role choices as list of dicts for API."""
        return [{'value': code, 'label': label} for code, label in cls.ROLE_CHOICES]
    
    @classmethod
    def get_department_choices_list(cls):
        """Return department choices as list of dicts for API."""
        return [{'value': code, 'label': label} for code, label in cls.DEPARTMENT_CHOICES]
    
    @classmethod
    def is_valid_role(cls, role):
        """Check if role value is valid."""
        return role in dict(cls.ROLE_CHOICES)
    
    @classmethod
    def is_valid_department(cls, department):
        """Check if department value is valid."""
        return department in dict(cls.DEPARTMENT_CHOICES) or department == ''


class ProfileChangeLog(models.Model):
    """
    Audit log for profile changes, especially role and department changes.
    
    SECURITY: This provides audit trail for access control changes.
    """
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='profile_changes')
    changed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='profile_changes_made')
    field_name = models.CharField(max_length=64)
    old_value = models.CharField(max_length=256, blank=True)
    new_value = models.CharField(max_length=256, blank=True)
    changed_at = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    
    class Meta:
        ordering = ['-changed_at']
        indexes = [
            models.Index(fields=['user', 'changed_at']),
            models.Index(fields=['field_name', 'changed_at']),
        ]
    
    def __str__(self):
        return f"{self.user.username}: {self.field_name} changed at {self.changed_at}"
