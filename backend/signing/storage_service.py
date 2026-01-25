"""
Signed PDF Storage Service

This service handles:
- Storing signed PDF files to disk
- Retrieving files for download
- Managing file expiration
- Cleanup of expired files

File Storage Structure:
    SIGNED_PDF_STORAGE_DIR/
    └── {year}/
        └── {month}/
            └── {user_id}/
                └── {uuid}_{timestamp}.pdf

Security Considerations:
- Files are stored outside web root
- File names are randomized (UUID) to prevent enumeration
- Access control is enforced at API level
- Path traversal is prevented by validation
"""

import os
import uuid
import logging
import hashlib
from pathlib import Path
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)


class SignedPDFStorageService:
    """
    Service for managing signed PDF file storage.
    
    Usage:
        service = SignedPDFStorageService()
        
        # Store a signed PDF
        file_path = service.store_signed_pdf(user, pdf_content, original_filename)
        
        # Get file for download
        full_path = service.get_file_path(relative_path)
        
        # Cleanup expired files
        deleted_count = service.cleanup_expired_files()
    """
    
    def __init__(self):
        self.storage_dir = Path(settings.SIGNED_PDF_STORAGE_DIR)
        self.retention_days = getattr(settings, 'SIGNED_PDF_RETENTION_DAYS', 14)
        self.max_file_size = getattr(settings, 'SIGNED_PDF_MAX_SIZE', 52428800)
        
        # Ensure storage directory exists
        self._ensure_storage_dir()
    
    def _ensure_storage_dir(self):
        """Create storage directory if it doesn't exist."""
        if not self.storage_dir.exists():
            self.storage_dir.mkdir(parents=True, mode=0o750)
            logger.info(f"Created signed PDF storage directory: {self.storage_dir}")
    
    def _get_user_storage_path(self, user_id):
        """
        Get the storage path for a user's signed PDFs.
        
        Structure: {year}/{month}/{user_id}/
        """
        now = timezone.now()
        year = now.strftime('%Y')
        month = now.strftime('%m')
        
        return Path(year) / month / str(user_id)
    
    def _generate_filename(self, original_filename):
        """
        Generate a unique filename for storage.
        
        Format: {uuid}_{timestamp}.pdf
        """
        file_uuid = uuid.uuid4().hex[:12]
        timestamp = timezone.now().strftime('%Y%m%d%H%M%S')
        
        # Sanitize original filename for logging (not used in storage)
        safe_original = "".join(c for c in original_filename if c.isalnum() or c in '._-')[:50]
        
        return f"{file_uuid}_{timestamp}.pdf"
    
    def _validate_path(self, path):
        """
        Validate that a path doesn't attempt directory traversal.
        
        Security: Prevent path traversal attacks.
        """
        path_str = str(path)
        
        if '..' in path_str:
            raise ValueError("Invalid path: directory traversal detected")
        
        if path_str.startswith('/') or path_str.startswith('\\'):
            raise ValueError("Invalid path: absolute path not allowed")
        
        return True
    
    def store_signed_pdf(self, user, pdf_content, original_filename):
        """
        Store a signed PDF file and return the relative path.
        
        Args:
            user: Django User object
            pdf_content: bytes - The signed PDF content
            original_filename: str - Original filename for reference
        
        Returns:
            tuple: (relative_file_path, expires_at)
        
        Raises:
            ValueError: If file is too large or invalid
        """
        # Validate file size
        if len(pdf_content) > self.max_file_size:
            raise ValueError(f"File too large. Maximum size is {self.max_file_size} bytes")
        
        # Validate PDF header
        if not pdf_content.startswith(b'%PDF'):
            raise ValueError("Invalid PDF file")
        
        # Generate storage path
        user_path = self._get_user_storage_path(user.id)
        filename = self._generate_filename(original_filename)
        relative_path = user_path / filename
        
        # Create full path
        full_path = self.storage_dir / relative_path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write file
        try:
            with open(full_path, 'wb') as f:
                f.write(pdf_content)
            
            # Set restrictive permissions
            os.chmod(full_path, 0o640)
            
            logger.info(f"Stored signed PDF: {relative_path} ({len(pdf_content)} bytes)")
            
        except IOError as e:
            logger.error(f"Failed to store signed PDF: {e}")
            raise ValueError(f"Failed to store file: {e}")
        
        # Calculate expiration
        expires_at = timezone.now() + timedelta(days=self.retention_days)
        
        return str(relative_path), expires_at
    
    def get_file_path(self, relative_path):
        """
        Get the full filesystem path for a stored file.
        
        Args:
            relative_path: str - Relative path from storage
        
        Returns:
            Path object or None if file doesn't exist
        
        Raises:
            ValueError: If path is invalid (traversal attempt)
        """
        if not relative_path:
            return None
        
        self._validate_path(relative_path)
        
        full_path = self.storage_dir / relative_path
        
        # Security: Ensure resolved path is within storage directory
        try:
            full_path = full_path.resolve()
            if not str(full_path).startswith(str(self.storage_dir.resolve())):
                logger.warning(f"Path traversal attempt detected: {relative_path}")
                raise ValueError("Invalid path")
        except Exception as e:
            logger.warning(f"Path resolution error: {e}")
            raise ValueError("Invalid path")
        
        if not full_path.exists():
            return None
        
        return full_path
    
    def delete_file(self, relative_path):
        """
        Delete a stored file.
        
        Args:
            relative_path: str - Relative path to delete
        
        Returns:
            bool - True if deleted, False if not found
        """
        if not relative_path:
            return False
        
        try:
            full_path = self.get_file_path(relative_path)
            if full_path and full_path.exists():
                os.unlink(full_path)
                logger.info(f"Deleted signed PDF: {relative_path}")
                return True
        except Exception as e:
            logger.error(f"Failed to delete file {relative_path}: {e}")
        
        return False
    
    def cleanup_expired_files(self, dry_run=False):
        """
        Clean up expired signed PDF files.
        
        This method should be called by a scheduled task (cron/Celery).
        
        Args:
            dry_run: bool - If True, only report what would be deleted
        
        Returns:
            dict - Statistics about the cleanup operation
        """
        from usercerts.models import SigningHistory
        
        now = timezone.now()
        stats = {
            'checked': 0,
            'deleted': 0,
            'failed': 0,
            'already_deleted': 0,
            'dry_run': dry_run
        }
        
        # Find expired records with files
        expired_records = SigningHistory.objects.filter(
            expires_at__lt=now,
            status__in=['valid', 'revoked', 'expired'],
            file_path__gt=''  # Has a file path
        ).exclude(
            status='deleted'
        )
        
        logger.info(f"Cleanup: Found {expired_records.count()} expired records to process")
        
        for record in expired_records:
            stats['checked'] += 1
            
            if dry_run:
                logger.info(f"[DRY RUN] Would delete: {record.file_path}")
                stats['deleted'] += 1
                continue
            
            try:
                # Delete the file
                if self.delete_file(record.file_path):
                    # Mark record as deleted
                    record.mark_deleted()
                    stats['deleted'] += 1
                else:
                    # File already missing, just update status
                    record.mark_deleted()
                    stats['already_deleted'] += 1
                    
            except Exception as e:
                logger.error(f"Failed to cleanup record {record.id}: {e}")
                stats['failed'] += 1
        
        logger.info(f"Cleanup complete: {stats}")
        return stats
    
    def get_storage_stats(self):
        """
        Get storage statistics.
        
        Returns:
            dict - Storage statistics
        """
        from usercerts.models import SigningHistory
        
        total_files = SigningHistory.objects.filter(
            file_path__gt='',
            status__in=['valid', 'revoked']
        ).count()
        
        from django.db.models import Sum
        total_size = SigningHistory.objects.filter(
            file_path__gt='',
            status__in=['valid', 'revoked']
        ).aggregate(
            total=Sum('document_size')
        )['total'] or 0
        
        expired_count = SigningHistory.objects.filter(
            expires_at__lt=timezone.now(),
            file_path__gt='',
            status__in=['valid', 'revoked']
        ).count()
        
        return {
            'total_files': total_files,
            'total_size_bytes': total_size,
            'total_size_mb': round(total_size / (1024 * 1024), 2),
            'expired_pending_cleanup': expired_count,
            'retention_days': self.retention_days,
            'storage_dir': str(self.storage_dir)
        }
