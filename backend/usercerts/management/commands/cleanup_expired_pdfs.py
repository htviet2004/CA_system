"""
Management command to clean up expired signed PDF files.

This command should be run periodically (e.g., via cron job or Celery beat)
to remove signed PDFs that have passed their retention period.

Usage:
    # Dry run - shows what would be deleted without actually deleting
    python manage.py cleanup_expired_pdfs --dry-run
    
    # Actually perform cleanup
    python manage.py cleanup_expired_pdfs
    
    # With verbose output
    python manage.py cleanup_expired_pdfs --verbosity 2

Cron job example (run daily at 2 AM):
    0 2 * * * cd /path/to/backend && /path/to/venv/bin/python manage.py cleanup_expired_pdfs >> /var/log/pdf_cleanup.log 2>&1

Celery periodic task example:
    CELERY_BEAT_SCHEDULE = {
        'cleanup-expired-pdfs': {
            'task': 'usercerts.tasks.cleanup_expired_pdfs',
            'schedule': crontab(hour=2, minute=0),  # Run daily at 2 AM
        },
    }
"""
import logging
from django.core.management.base import BaseCommand
from django.utils import timezone

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Clean up expired signed PDF files that have passed their retention period'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be deleted without actually deleting',
        )
        parser.add_argument(
            '--batch-size',
            type=int,
            default=100,
            help='Number of records to process per batch (default: 100)',
        )

    def handle(self, *args, **options):
        from signing.storage_service import SignedPDFStorageService
        
        dry_run = options['dry_run']
        batch_size = options['batch_size']
        verbosity = options['verbosity']
        
        self.stdout.write(
            self.style.NOTICE(
                f"{'[DRY RUN] ' if dry_run else ''}Starting expired PDF cleanup..."
            )
        )
        
        try:
            storage_service = SignedPDFStorageService()
            result = storage_service.cleanup_expired_files(dry_run=dry_run)
            
            # Log summary
            if result['deleted_count'] > 0 or result['failed_count'] > 0:
                self.stdout.write(
                    self.style.SUCCESS(
                        f"{'[DRY RUN] Would delete' if dry_run else 'Deleted'}: "
                        f"{result['deleted_count']} files, "
                        f"Freed: {self._format_size(result['freed_bytes'])}"
                    )
                )
                
                if result['failed_count'] > 0:
                    self.stdout.write(
                        self.style.WARNING(
                            f"Failed to delete: {result['failed_count']} files"
                        )
                    )
                    
                    if verbosity >= 2:
                        for error in result['errors'][:10]:  # Show first 10 errors
                            self.stdout.write(
                                self.style.ERROR(f"  - {error}")
                            )
                
                if verbosity >= 2:
                    self.stdout.write(
                        self.style.NOTICE(f"Deleted file paths:")
                    )
                    for path in result['deleted_files'][:20]:  # Show first 20
                        self.stdout.write(f"  - {path}")
            else:
                self.stdout.write(
                    self.style.SUCCESS("No expired files to clean up")
                )
            
            # Log to standard logger for monitoring
            logger.info(
                f"PDF cleanup completed: deleted={result['deleted_count']}, "
                f"failed={result['failed_count']}, freed_bytes={result['freed_bytes']}"
            )
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f"Cleanup failed with error: {e}")
            )
            logger.exception("PDF cleanup command failed")
            raise
    
    def _format_size(self, size_bytes):
        """Format bytes to human-readable size."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if abs(size_bytes) < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} TB"
