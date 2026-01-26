"""
Signed PDF Download and History API Views

Provides endpoints for:
- Listing user's signed PDFs
- Downloading signed PDFs (with permission and expiration checks)
- Getting signing history details
- Storage statistics (admin only)

Security:
- All endpoints require authentication
- Users can only access their own files
- Expiration is enforced at download time
- Path traversal is prevented
"""

import logging

from django.http import JsonResponse, FileResponse
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from django.conf import settings

from usercerts.models import SigningHistory, UserCert
from .storage_service import SignedPDFStorageService

logger = logging.getLogger(__name__)


def _get_client_ip(request):
    """Extract client IP from request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')


@login_required
@require_http_methods(["GET"])
def list_signed_documents(request):
    """
    List all signed documents for the current user.
    
    Query parameters:
        - page: Page number (default: 1)
        - limit: Items per page (default: 20, max: 100)
        - status: Filter by status (valid, revoked, expired, deleted)
        - include_expired: Include expired documents (default: false)
    
    Response:
        {
            "documents": [...],
            "total": 100,
            "page": 1,
            "limit": 20,
            "has_more": true
        }
    """
    user = request.user
    
    # Pagination
    try:
        page = max(1, int(request.GET.get('page', 1)))
        limit = min(100, max(1, int(request.GET.get('limit', 20))))
    except ValueError:
        page, limit = 1, 20
    
    offset = (page - 1) * limit
    
    # Base queryset
    queryset = SigningHistory.objects.filter(user=user)
    
    # Status filter
    status_filter = request.GET.get('status', '')
    if status_filter and status_filter in ['valid', 'revoked', 'expired', 'deleted']:
        queryset = queryset.filter(status=status_filter)
    
    # Expired filter
    include_expired = request.GET.get('include_expired', 'false').lower() == 'true'
    if not include_expired:
        queryset = queryset.exclude(status='deleted')
    
    # Get total count
    total = queryset.count()
    
    # Get paginated results
    documents = queryset.order_by('-signed_at')[offset:offset + limit]
    
    # Format response
    now = timezone.now()
    result = []
    for doc in documents:
        is_expired = doc.expires_at and doc.expires_at < now
        
        result.append({
            'id': doc.id,
            'document_name': doc.document_name,
            'document_hash': doc.document_hash,
            'document_size': doc.document_size,
            'signed_at': doc.signed_at.isoformat(),
            'expires_at': doc.expires_at.isoformat() if doc.expires_at else None,
            'reason': doc.reason,
            'status': doc.status,
            'is_expired': is_expired,
            'is_downloadable': doc.is_downloadable(),
            'download_count': doc.download_count,
            'last_downloaded_at': doc.last_downloaded_at.isoformat() if doc.last_downloaded_at else None,
            'certificate_cn': doc.certificate.common_name if doc.certificate else None,
        })
    
    return JsonResponse({
        'documents': result,
        'total': total,
        'page': page,
        'limit': limit,
        'has_more': offset + limit < total
    })


@login_required
@require_http_methods(["GET"])
def get_signed_document_detail(request, document_id):
    """
    Get detailed information about a specific signed document.
    
    Path parameters:
        - document_id: ID of the signing history record
    
    Response:
        {
            "id": 1,
            "document_name": "contract.pdf",
            "document_hash": "abc123...",
            ...
        }
    """
    user = request.user
    
    try:
        doc = SigningHistory.objects.select_related('certificate', 'certificate__user').get(
            id=document_id,
            user=user
        )
    except SigningHistory.DoesNotExist:
        return JsonResponse({'error': 'Document not found'}, status=404)
    
    now = timezone.now()
    is_expired = doc.expires_at and doc.expires_at < now
    
    # Calculate days until expiration
    days_until_expiry = None
    if doc.expires_at and not is_expired:
        days_until_expiry = (doc.expires_at - now).days
    
    return JsonResponse({
        'id': doc.id,
        'document_name': doc.document_name,
        'document_hash': doc.document_hash,
        'document_size': doc.document_size,
        'signed_at': doc.signed_at.isoformat(),
        'expires_at': doc.expires_at.isoformat() if doc.expires_at else None,
        'days_until_expiry': days_until_expiry,
        'reason': doc.reason,
        'status': doc.status,
        'is_expired': is_expired,
        'is_downloadable': doc.is_downloadable(),
        'download_count': doc.download_count,
        'last_downloaded_at': doc.last_downloaded_at.isoformat() if doc.last_downloaded_at else None,
        'ip_address': doc.ip_address,
        'certificate': {
            'id': doc.certificate.id,
            'common_name': doc.certificate.common_name,
            'serial_number': doc.certificate.serial_number,
            'active': doc.certificate.active,
        } if doc.certificate else None,
        'created_at': doc.created_at.isoformat(),
        'updated_at': doc.updated_at.isoformat(),
    })


@login_required
@require_http_methods(["GET"])
def download_signed_document(request, document_id):
    """
    Download a signed PDF document.
    
    Path parameters:
        - document_id: ID of the signing history record
    
    Security checks:
        - User must own the document
        - Document must not be expired
        - Document must have a stored file
        - File must exist on disk
    
    Returns:
        - 200: PDF file as attachment
        - 403: Access denied
        - 404: Document or file not found
        - 410: Document expired (Gone)
    """
    user = request.user
    
    # Get document record
    try:
        doc = SigningHistory.objects.get(
            id=document_id,
            user=user
        )
    except SigningHistory.DoesNotExist:
        return JsonResponse({
            'error': 'Document not found',
            'error_code': 'NOT_FOUND'
        }, status=404)
    
    # Check if file path exists
    if not doc.file_path:
        return JsonResponse({
            'error': 'File not available for this document',
            'error_code': 'NO_FILE'
        }, status=404)
    
    # Check expiration
    if doc.is_expired():
        return JsonResponse({
            'error': 'Document has expired and is no longer available for download',
            'error_code': 'EXPIRED',
            'expired_at': doc.expires_at.isoformat() if doc.expires_at else None
        }, status=410)  # 410 Gone
    
    # Check status
    if doc.status == 'deleted':
        return JsonResponse({
            'error': 'Document has been deleted',
            'error_code': 'DELETED'
        }, status=410)
    
    # Get file from storage
    storage_service = SignedPDFStorageService()
    
    try:
        file_path = storage_service.get_file_path(doc.file_path)
    except ValueError as e:
        logger.error(f"Invalid file path for document {document_id}: {e}")
        return JsonResponse({
            'error': 'Invalid file path',
            'error_code': 'INVALID_PATH'
        }, status=500)
    
    if not file_path or not file_path.exists():
        logger.warning(f"File not found for document {document_id}: {doc.file_path}")
        return JsonResponse({
            'error': 'File not found on server',
            'error_code': 'FILE_MISSING'
        }, status=404)
    
    # Increment download counter
    doc.increment_download()
    
    # Log download
    logger.info(f"Document {document_id} downloaded by {user.username} from {_get_client_ip(request)}")
    
    # Return file
    response = FileResponse(
        open(file_path, 'rb'),
        as_attachment=True,
        filename=doc.document_name
    )
    
    # Add headers
    response['X-Document-Hash'] = doc.document_hash
    response['X-Download-Count'] = str(doc.download_count)
    
    return response


@login_required
@require_http_methods(["GET"])
def get_signing_history_stats(request):
    """
    Get signing statistics for the current user.
    
    Response:
        {
            "total_signed": 100,
            "valid_signatures": 95,
            "revoked_signatures": 3,
            "expired_signatures": 2,
            "this_month": 10,
            "last_30_days": 15,
            "total_download_count": 250,
            "storage_used_bytes": 52428800
        }
    """
    from datetime import timedelta
    from django.db.models import Sum, Count
    
    user = request.user
    now = timezone.now()
    
    # Base queryset
    queryset = SigningHistory.objects.filter(user=user)
    
    # Basic counts
    total_signed = queryset.count()
    valid_signatures = queryset.filter(status='valid').count()
    revoked_signatures = queryset.filter(status='revoked').count()
    
    # Time-based counts
    start_of_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    this_month = queryset.filter(signed_at__gte=start_of_month).count()
    
    last_30_days = queryset.filter(
        signed_at__gte=now - timedelta(days=30)
    ).count()
    
    # Download and storage stats
    stats = queryset.aggregate(
        total_downloads=Sum('download_count'),
        total_storage=Sum('document_size')
    )
    
    # Available for download (not expired, has file)
    downloadable_count = queryset.filter(
        file_path__gt='',
        status__in=['valid', 'revoked']
    ).exclude(
        expires_at__lt=now
    ).count()
    
    return JsonResponse({
        'total_signed': total_signed,
        'valid_signatures': valid_signatures,
        'revoked_signatures': revoked_signatures,
        'this_month': this_month,
        'last_30_days': last_30_days,
        'total_download_count': stats['total_downloads'] or 0,
        'storage_used_bytes': stats['total_storage'] or 0,
        'downloadable_documents': downloadable_count
    })


@login_required
@require_http_methods(["GET"])
def get_storage_stats(request):
    """
    Get storage statistics (admin only).
    
    Response:
        {
            "total_files": 1000,
            "total_size_mb": 512.5,
            "expired_pending_cleanup": 50,
            "retention_days": 14
        }
    """
    if not request.user.is_staff:
        return JsonResponse({'error': 'Admin access required'}, status=403)
    
    storage_service = SignedPDFStorageService()
    stats = storage_service.get_storage_stats()
    
    return JsonResponse(stats)


@login_required
@require_http_methods(["POST"])
def run_cleanup(request):
    """
    Run storage cleanup (admin only).
    
    Query parameters:
        - dry_run: If 'true', only report what would be deleted
    
    Response:
        {
            "checked": 100,
            "deleted": 50,
            "failed": 2,
            "dry_run": false
        }
    """
    if not request.user.is_staff:
        return JsonResponse({'error': 'Admin access required'}, status=403)
    
    dry_run = request.GET.get('dry_run', 'false').lower() == 'true'
    
    storage_service = SignedPDFStorageService()
    stats = storage_service.cleanup_expired_files(dry_run=dry_run)
    
    logger.info(f"Storage cleanup run by {request.user.username}: {stats}")
    
    return JsonResponse(stats)
