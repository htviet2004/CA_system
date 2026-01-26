from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import datetime, timedelta
import uuid


class SignedPDF(models.Model):
    """
    Model lưu trữ PDF đã ký (cache tạm thời).
    Chỉ lưu metadata: ID, tên file, thời gian ký.
    File PDF được lưu trực tiếp trong hệ thống tập tin.
    """
    # ID unique cho mỗi PDF đã ký
    pdf_id = models.CharField(max_length=36, unique=True, default=uuid.uuid4)
    
    # User liên kết
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='signed_pdfs_cache')
    
    # Tên file PDF
    filename = models.CharField(max_length=255)
    
    # Thời gian ký
    signed_at = models.DateTimeField(auto_now_add=True)
    
    # Thời gian tạo record (dùng cho TTL)
    created_at = models.DateTimeField(auto_now_add=True)
    
    # Trạng thái (True = còn trong cache, False = đã hết hạn nhưng vẫn giữ trong log)
    is_cached = models.BooleanField(default=True)
    
    class Meta:
        ordering = ['-signed_at']
        indexes = [
            models.Index(fields=['user', '-signed_at']),
            models.Index(fields=['pdf_id']),
            models.Index(fields=['user', 'is_cached']),
        ]
    
    def __str__(self):
        return f"{self.user.username} - {self.filename} ({self.pdf_id})"
    
    def is_expired(self, ttl_seconds=3600):
        """Kiểm tra xem đã hết hạn cache chưa (nhưng vẫn giữ trong log)"""
        # So sánh aware datetime với aware datetime
        elapsed = (timezone.now() - self.created_at).total_seconds()
        return elapsed > ttl_seconds
    
    def mark_expired(self):
        """Đánh dấu là hết hạn cache (nhưng vẫn giữ trong log)"""
        self.is_cached = False
        self.save()
