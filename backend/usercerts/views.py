"""
User certificate management views.

SECURITY: All endpoints require authentication and CSRF protection.
"""

import os
import logging
from pathlib import Path

from django.conf import settings
from django.http import JsonResponse, FileResponse
from django.views.decorators.http import require_http_methods
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.utils import timezone

from .models import UserCert, SigningHistory, CertificateRevocationLog
from signing.utils import get_fernet
from signing.validators import validate_username, validate_p12_upload, validate_common_name

logger = logging.getLogger(__name__)


def _is_admin(request):
    """Check if request user is authenticated admin."""
    return request.user.is_authenticated and request.user.is_staff


@login_required
def list_certs(request):
    """
    List certificates - all for admin, own for users.
    
    SECURITY: Users can only see their own certificates.
    """
    if request.user.is_staff:
        qs = UserCert.objects.all().select_related('user', 'revoked_by')
    else:
        qs = UserCert.objects.filter(user=request.user).select_related('user')
    
    out = []
    for c in qs:
        cert_data = {
            'id': c.id, 
            'user': c.user.username, 
            'cn': c.common_name, 
            'serial_number': c.serial_number,
            'created_at': c.created_at.isoformat(), 
            'expires_at': c.expires_at.isoformat() if c.expires_at else None,
            'active': c.active,
            'revoked_at': c.revoked_at.isoformat() if c.revoked_at else None,
            'revocation_reason': c.revocation_reason,
            'revoked_by': c.revoked_by.username if c.revoked_by else None,
        }
        out.append(cert_data)
    
    return JsonResponse({'certs': out})


@login_required
@require_http_methods(["POST"])
def upload_p12(request):
    """
    Upload a PKCS#12 certificate file.
    
    SECURITY: Validates file, encrypts before storage.
    """
    uploaded = request.FILES.get('file')
    passphrase = request.POST.get('passphrase', '')
    
    # SECURITY: Validate uploaded file
    try:
        validate_p12_upload(uploaded)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)
    
    user = request.user
    username = user.username

    user_dir = Path(settings.BASE_DIR) / 'users' / username
    os.makedirs(user_dir, exist_ok=True)
    
    # SECURITY: Store encrypted, not plaintext
    f = get_fernet()
    enc = f.encrypt(uploaded.read())
    p12_enc_path = user_dir / 'user.p12.enc'
    p12_enc_path.write_bytes(enc)
    pass_enc_path = user_dir / 'p12.pass.enc'
    pass_enc_path.write_bytes(f.encrypt(passphrase.encode('utf-8')))

    uc = UserCert.objects.create(
        user=user, 
        common_name=username, 
        p12_enc_path=str(p12_enc_path.relative_to(settings.BASE_DIR)), 
        p12_pass_enc_path=str(pass_enc_path.relative_to(settings.BASE_DIR))
    )
    logger.info(f"P12 uploaded for user: {username}")
    return JsonResponse({'ok': True, 'id': uc.id})


@login_required
@require_http_methods(["POST"])
def issue_cert(request):
    """
    Issue a new certificate for the authenticated user.
    
    SECURITY: Uses centralized certificate issuer with secure practices.
    """
    from signing.certificate_issuer import issue_user_certificate
    
    # SECURITY: Use session-authenticated user
    user = request.user
    username = user.username
    cn = request.POST.get('cn', username)
    
    # SECURITY: Validate common name
    try:
        cn = validate_common_name(cn)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)
    
    # Use centralized certificate issuer
    result = issue_user_certificate(username, common_name=cn)
    
    if not result.get('ok'):
        logger.error(f"Certificate issuance failed for {username}: {result.get('error')}")
        return JsonResponse({'error': 'Certificate generation failed'}, status=500)
    
    uc = UserCert.objects.create(
        user=user, 
        common_name=cn,
        serial_number=result.get('serial_number', ''),
        p12_enc_path=result.get('p12_enc_path', ''), 
        p12_pass_enc_path=result.get('p12_pass_enc_path', ''),
        valid_from=result.get('valid_from'),
        expires_at=result.get('expires_at')
    )
    logger.info(f"Certificate issued for user: {username}")
    
    return JsonResponse({'ok': True, 'id': uc.id})


def _secure_delete_file(filepath):
    """
    Securely delete a file by overwriting before unlinking.
    
    SECURITY: Prevents recovery of sensitive files like private keys.
    """
    try:
        filepath = Path(filepath)
        if not filepath.exists():
            return
        
        # Overwrite with random data
        file_size = filepath.stat().st_size
        with open(filepath, 'wb') as f:
            f.write(os.urandom(file_size))
            f.flush()
            os.fsync(f.fileno())
        
        # Then delete
        filepath.unlink()
        logger.debug(f"Securely deleted: {filepath}")
    except Exception as e:
        logger.warning(f"Failed to securely delete {filepath}: {e}")
        try:
            Path(filepath).unlink()
        except Exception:
            pass


@login_required
def download_p12(request, pk):
    """
    Download encrypted P12 certificate.
    
    SECURITY: Users can only download their own certificates.
    """
    try:
        uc = UserCert.objects.get(pk=pk)
    except UserCert.DoesNotExist:
        return JsonResponse({'error': 'not found'}, status=404)
    
    if uc.user != request.user and not request.user.is_staff:
        return JsonResponse({'error': 'forbidden'}, status=403)
    
    # Construct full path
    p12_path = Path(settings.BASE_DIR) / uc.p12_enc_path
    if not p12_path.exists():
        return JsonResponse({'error': 'certificate file not found'}, status=404)
    
    return FileResponse(
        open(p12_path, 'rb'), 
        as_attachment=True, 
        filename=os.path.basename(uc.p12_enc_path)
    )


@login_required
@require_http_methods(["POST"])
def revoke_cert(request, pk):
    """
    Revoke a certificate (admin only or own certificate).
    Also revokes all signatures made with this certificate.
    
    SECURITY: Logs revocation for audit trail.
    """
    try:
        uc = UserCert.objects.get(pk=pk)
    except UserCert.DoesNotExist:
        return JsonResponse({'error': 'not found'}, status=404)
    
    # Only admin or cert owner can revoke
    if uc.user != request.user and not request.user.is_staff:
        return JsonResponse({'error': 'forbidden'}, status=403)
    
    reason = request.POST.get('reason', 'unspecified')
    notes = request.POST.get('notes', '')
    
    # Revoke the certificate
    uc.revoke(reason=reason, revoked_by=request.user)
    
    # Create revocation log entry
    CertificateRevocationLog.objects.create(
        certificate=uc,
        revoked_by=request.user,
        reason=reason,
        notes=notes
    )
    
    logger.info(f"Certificate revoked: {uc.common_name} by {request.user.username}, reason: {reason}")
    
    return JsonResponse({
        'ok': True,
        'message': f'Certificate {uc.common_name} revoked successfully',
        'revoked_signatures_count': SigningHistory.objects.filter(
            certificate=uc, 
            status='revoked'
        ).count()
    })


# ============================================================================
# SIGNING HISTORY APIs
# ============================================================================

@login_required
def list_signing_history(request):
    """
    List signing history.
    Admin: all records
    User: own records only
    
    SECURITY: Users can only see their own signing history.
    """
    if request.user.is_staff:
        qs = SigningHistory.objects.all()
    else:
        qs = SigningHistory.objects.filter(user=request.user)
    
    qs = qs.select_related('user', 'certificate', 'revoked_by').order_by('-signed_at')
    
    # Pagination - validate inputs
    try:
        limit = min(int(request.GET.get('limit', 50)), 200)  # SECURITY: Max 200 per page
        offset = max(int(request.GET.get('offset', 0)), 0)
    except ValueError:
        limit, offset = 50, 0
    
    total = qs.count()
    qs = qs[offset:offset+limit]
    
    history = []
    for h in qs:
        history.append({
            'id': h.id,
            'user': h.user.username,
            'document_name': h.document_name,
            'document_hash': h.document_hash,
            'document_size': h.document_size,
            'signed_at': h.signed_at.isoformat(),
            'reason': h.reason,
            'location': h.location,
            'status': h.status,
            'certificate_cn': h.certificate.common_name if h.certificate else None,
            'certificate_active': h.certificate.active if h.certificate else None,
            'revoked_at': h.revoked_at.isoformat() if h.revoked_at else None,
            'revoked_by': h.revoked_by.username if h.revoked_by else None,
            'revocation_reason': h.revocation_reason,
        })
    
    return JsonResponse({
        'history': history,
        'total': total,
        'limit': limit,
        'offset': offset
    })


@login_required
def signing_history_by_user(request, username):
    """
    Get signing history for a specific user.
    
    SECURITY: Users can only view their own history. Admins can view all.
    """
    # SECURITY: Validate username format
    try:
        username = validate_username(username)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)
    
    # Only admin or the user themselves can view
    if request.user.username != username and not request.user.is_staff:
        return JsonResponse({'error': 'forbidden'}, status=403)
    
    try:
        target_user = User.objects.get(username=username)
    except User.DoesNotExist:
        return JsonResponse({'error': 'user not found'}, status=404)
    
    qs = SigningHistory.objects.filter(user=target_user).select_related(
        'certificate', 'revoked_by'
    ).order_by('-signed_at')
    
    history = []
    for h in qs:
        history.append({
            'id': h.id,
            'document_name': h.document_name,
            'document_hash': h.document_hash,
            'signed_at': h.signed_at.isoformat(),
            'status': h.status,
            'certificate_cn': h.certificate.common_name if h.certificate else None,
        })
    
    return JsonResponse({
        'user': username,
        'history': history,
        'total': len(history)
    })


@login_required
def signing_history_by_document(request, doc_hash):
    """
    Get signing history for a specific document (by hash).
    Useful for verifying document authenticity.
    
    SECURITY: Non-admins can only see their own signatures on the document.
    """
    # SECURITY: Validate doc_hash format (should be hex SHA-256)
    if not doc_hash or len(doc_hash) != 64 or not all(c in '0123456789abcdef' for c in doc_hash.lower()):
        return JsonResponse({'error': 'invalid document hash format'}, status=400)
    
    qs = SigningHistory.objects.filter(document_hash=doc_hash).select_related(
        'user', 'certificate', 'revoked_by'
    ).order_by('-signed_at')
    
    # Non-admin can only see their own records
    if not request.user.is_staff:
        qs = qs.filter(user=request.user)
    
    history = []
    for h in qs:
        history.append({
            'id': h.id,
            'user': h.user.username,
            'document_name': h.document_name,
            'signed_at': h.signed_at.isoformat(),
            'status': h.status,
            'reason': h.reason,
            'location': h.location,
            'certificate_cn': h.certificate.common_name if h.certificate else None,
            'certificate_active': h.certificate.active if h.certificate else None,
        })
    
    return JsonResponse({
        'document_hash': doc_hash,
        'signatures': history,
        'count': len(history),
        'has_valid_signature': any(h['status'] == 'valid' for h in history)
    })


@login_required
@require_http_methods(["POST"])
def revoke_signature(request, pk):
    """
    Revoke a specific signature (admin only).
    Does not revoke the certificate, only this signature.
    
    SECURITY: Admin-only operation with audit logging.
    """
    if not _is_admin(request):
        return JsonResponse({'error': 'admin required'}, status=403)
    
    try:
        sig = SigningHistory.objects.get(pk=pk)
    except SigningHistory.DoesNotExist:
        return JsonResponse({'error': 'signature not found'}, status=404)
    
    if sig.status == 'revoked':
        return JsonResponse({'error': 'signature already revoked'}, status=400)
    
    reason = request.POST.get('reason', 'Admin revocation')
    sig.revoke(reason=reason, revoked_by=request.user)
    
    logger.info(f"Signature revoked: {pk} by {request.user.username}, reason: {reason}")
    
    return JsonResponse({
        'ok': True,
        'message': f'Signature {pk} revoked successfully',
        'signature_id': pk,
        'document_name': sig.document_name,
        'user': sig.user.username
    })


# ============================================================================
# REVOCATION MANAGEMENT APIs
# ============================================================================

@login_required
def revocation_log(request):
    """
    Get revocation log (admin only).
    Shows all certificate revocations for audit.
    
    SECURITY: Admin-only audit endpoint.
    """
    if not _is_admin(request):
        return JsonResponse({'error': 'admin required'}, status=403)
    
    logs = CertificateRevocationLog.objects.all().select_related(
        'certificate', 'certificate__user', 'revoked_by'
    ).order_by('-revoked_at')
    
    out = []
    for log in logs:
        out.append({
            'id': log.id,
            'certificate_id': log.certificate.id,
            'certificate_cn': log.certificate.common_name,
            'certificate_user': log.certificate.user.username,
            'revoked_by': log.revoked_by.username if log.revoked_by else None,
            'revoked_at': log.revoked_at.isoformat(),
            'reason': log.reason,
            'notes': log.notes,
        })
    
    return JsonResponse({'revocation_log': out})


def check_revocation_status(request, serial_or_hash):
    """
    Check if a certificate (by serial) or signature (by doc hash) is revoked.
    Public endpoint for verification integration.
    
    SECURITY: Public read-only endpoint, no authentication required.
    Validates input format.
    """
    # SECURITY: Validate input format (serial or SHA-256 hash)
    if not serial_or_hash or len(serial_or_hash) > 64:
        return JsonResponse({'error': 'invalid identifier'}, status=400)
    
    # Only allow alphanumeric characters
    if not all(c.isalnum() for c in serial_or_hash):
        return JsonResponse({'error': 'invalid identifier format'}, status=400)
    
    # Check certificate by serial number
    cert = UserCert.objects.filter(serial_number=serial_or_hash).first()
    if cert:
        return JsonResponse({
            'type': 'certificate',
            'serial_number': cert.serial_number,
            'is_revoked': not cert.active,
            'revoked_at': cert.revoked_at.isoformat() if cert.revoked_at else None,
            'revocation_reason': cert.revocation_reason,
        })
    
    # Check signatures by document hash
    signatures = SigningHistory.objects.filter(document_hash=serial_or_hash.lower())
    if signatures.exists():
        revoked_count = signatures.filter(status='revoked').count()
        return JsonResponse({
            'type': 'document',
            'document_hash': serial_or_hash,
            'total_signatures': signatures.count(),
            'revoked_signatures': revoked_count,
            'has_valid_signature': signatures.filter(status='valid').exists(),
        })
    
    return JsonResponse({
        'error': 'not found',
        'message': 'No certificate or document found with this identifier'
    }, status=404)


# ============================================================================
# USER DASHBOARD APIs
# ============================================================================

@login_required
def get_certificate_info(request):
    """
    Get certificate information for the current user.
    Returns certificate status, validity, and details.
    """
    from datetime import datetime
    
    user = request.user
    
    # Get user's active certificate
    cert = UserCert.objects.filter(user=user, active=True).order_by('-created_at').first()
    
    if not cert:
        return JsonResponse({
            'has_certificate': False,
            'message': 'No active certificate found'
        })
    
    # Try to extract certificate info from file if not in database
    valid_from = cert.valid_from
    expires_at = cert.expires_at
    fingerprint = None
    
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        import hashlib
        
        p12_path = Path(settings.BASE_DIR) / cert.p12_enc_path
        if p12_path.exists():
            f = get_fernet()
            p12_data = f.decrypt(p12_path.read_bytes())
            pass_path = Path(settings.BASE_DIR) / cert.p12_pass_enc_path
            password = f.decrypt(pass_path.read_bytes())
            
            from cryptography.hazmat.primitives.serialization import pkcs12
            private_key, certificate, _ = pkcs12.load_key_and_certificates(
                p12_data, password, default_backend()
            )
            if certificate:
                # Get fingerprint
                cert_der = certificate.public_bytes(serialization.Encoding.DER)
                fingerprint = hashlib.sha256(cert_der).hexdigest().upper()
                fingerprint = ':'.join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2))
                
                # Extract validity dates if not in database
                if not valid_from:
                    valid_from = certificate.not_valid_before_utc
                if not expires_at:
                    expires_at = certificate.not_valid_after_utc
                
                # Update database if we extracted new info
                updated = False
                if not cert.valid_from and valid_from:
                    cert.valid_from = valid_from
                    updated = True
                if not cert.expires_at and expires_at:
                    cert.expires_at = expires_at
                    updated = True
                if not cert.serial_number and certificate.serial_number:
                    cert.serial_number = format(certificate.serial_number, 'X')
                    updated = True
                if updated:
                    cert.save()
                    logger.info(f"Updated certificate info for user {user.username}")
                    
    except Exception as e:
        logger.debug(f"Could not extract certificate info: {e}")
    
    # Calculate certificate status
    now = timezone.now()
    
    if not cert.active:
        status = 'revoked'
        days_remaining = 0
    elif expires_at and expires_at < now:
        status = 'expired'
        days_remaining = 0
    elif expires_at:
        days_remaining = (expires_at - now).days
        if days_remaining <= 30:
            status = 'warning'  # Expiring soon
        else:
            status = 'valid'
    else:
        status = 'valid'
        days_remaining = None
    
    return JsonResponse({
        'has_certificate': True,
        'id': cert.id,
        'common_name': cert.common_name,
        'serial_number': cert.serial_number,
        'issuer': 'CA System Intermediate CA',
        'status': status,
        'days_remaining': days_remaining,
        'created_at': cert.created_at.isoformat(),
        'valid_from': valid_from.isoformat() if valid_from else None,
        'expires_at': expires_at.isoformat() if expires_at else None,
        'revoked_at': cert.revoked_at.isoformat() if cert.revoked_at else None,
        'revocation_reason': cert.revocation_reason,
        'fingerprint': fingerprint
    })


@login_required
def get_signing_stats(request):
    """
    Get signing statistics for the current user.
    """
    from django.db.models import Count
    from django.utils import timezone
    from datetime import timedelta
    
    user = request.user
    
    # Get all signing history for user
    all_signatures = SigningHistory.objects.filter(user=user)
    
    # Calculate statistics
    total_signed = all_signatures.count()
    valid_signatures = all_signatures.filter(status='valid').count()
    revoked_signatures = all_signatures.filter(status='revoked').count()
    
    # This month's signatures
    start_of_month = timezone.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    this_month = all_signatures.filter(signed_at__gte=start_of_month).count()
    
    # Last 30 days
    last_30_days = all_signatures.filter(
        signed_at__gte=timezone.now() - timedelta(days=30)
    ).count()
    
    return JsonResponse({
        'total_signed': total_signed,
        'valid_signatures': valid_signatures,
        'revoked_signatures': revoked_signatures,
        'this_month': this_month,
        'last_30_days': last_30_days
    })


@login_required
def download_certificate(request):
    """
    Download user's certificate in specified format.
    Formats: p12, pem, chain
    """
    from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, PrivateFormat, NoEncryption
    from cryptography.hazmat.backends import default_backend
    import tempfile
    
    format_type = request.GET.get('format', 'p12')
    
    if format_type not in ['p12', 'pem', 'chain']:
        return JsonResponse({'error': 'Invalid format. Use: p12, pem, chain'}, status=400)
    
    # Get user's active certificate
    cert = UserCert.objects.filter(user=request.user, active=True).order_by('-created_at').first()
    
    if not cert:
        return JsonResponse({'error': 'No active certificate found'}, status=404)
    
    p12_path = Path(settings.BASE_DIR) / cert.p12_enc_path
    if not p12_path.exists():
        return JsonResponse({'error': 'Certificate file not found'}, status=404)
    
    try:
        f = get_fernet()
        p12_data = f.decrypt(p12_path.read_bytes())
        pass_path = Path(settings.BASE_DIR) / cert.p12_pass_enc_path
        password = f.decrypt(pass_path.read_bytes())
        
        if format_type == 'p12':
            # Return the decrypted P12 file
            response = FileResponse(
                iter([p12_data]),
                content_type='application/x-pkcs12'
            )
            response['Content-Disposition'] = f'attachment; filename="{request.user.username}.p12"'
            return response
        
        # Parse P12 for PEM formats
        private_key, certificate, chain = pkcs12.load_key_and_certificates(
            p12_data, password, default_backend()
        )
        
        if format_type == 'pem':
            # Return certificate + private key as PEM
            pem_data = b''
            if certificate:
                pem_data += certificate.public_bytes(Encoding.PEM)
            if private_key:
                pem_data += private_key.private_bytes(
                    Encoding.PEM,
                    PrivateFormat.PKCS8,
                    NoEncryption()
                )
            
            response = FileResponse(
                iter([pem_data]),
                content_type='application/x-pem-file'
            )
            response['Content-Disposition'] = f'attachment; filename="{request.user.username}.pem"'
            return response
        
        elif format_type == 'chain':
            # Return certificate chain as PEM
            chain_data = b''
            if certificate:
                chain_data += certificate.public_bytes(Encoding.PEM)
            if chain:
                for ca_cert in chain:
                    chain_data += ca_cert.public_bytes(Encoding.PEM)
            
            response = FileResponse(
                iter([chain_data]),
                content_type='application/x-pem-file'
            )
            response['Content-Disposition'] = f'attachment; filename="{request.user.username}_chain.pem"'
            return response
        
    except Exception as e:
        logger.error(f"Certificate download error: {e}")
        return JsonResponse({'error': 'Failed to process certificate'}, status=500)


@login_required
@require_http_methods(["POST"])
def renew_certificate(request):
    """
    Request certificate renewal.
    Marks old certificate for renewal and issues a new one.
    """
    from signing.certificate_issuer import issue_user_certificate
    
    user = request.user
    
    # Get current active certificate
    old_cert = UserCert.objects.filter(user=user, active=True).order_by('-created_at').first()
    
    if not old_cert:
        return JsonResponse({'error': 'No active certificate to renew'}, status=404)
    
    # Check if certificate is renewable (within 60 days of expiry or expired)
    now = timezone.now()
    if old_cert.expires_at:
        days_remaining = (old_cert.expires_at - now).days
        if days_remaining > 60:
            return JsonResponse({
                'error': 'Certificate not eligible for renewal yet',
                'days_remaining': days_remaining,
                'eligible_in_days': days_remaining - 60
            }, status=400)
    
    # Issue new certificate
    result = issue_user_certificate(user.username, common_name=old_cert.common_name)
    
    if not result.get('ok'):
        logger.error(f"Certificate renewal failed for {user.username}: {result.get('error')}")
        return JsonResponse({'error': 'Certificate renewal failed'}, status=500)
    
    # Revoke old certificate
    old_cert.revoke(reason='superseded', revoked_by=user)
    
    # Create new certificate record
    new_cert = UserCert.objects.create(
        user=user,
        common_name=old_cert.common_name,
        serial_number=result.get('serial_number', ''),
        p12_enc_path=result.get('p12_enc_path', ''),
        p12_pass_enc_path=result.get('p12_pass_enc_path', ''),
        valid_from=result.get('valid_from'),
        expires_at=result.get('expires_at')
    )
    
    logger.info(f"Certificate renewed for user: {user.username}")
    
    return JsonResponse({
        'ok': True,
        'message': 'Certificate renewed successfully',
        'new_cert_id': new_cert.id,
        'old_cert_revoked': True
    })


# ============================================================================
# ADMIN-ONLY CERTIFICATE MANAGEMENT APIs
# ============================================================================

@login_required
@require_http_methods(["POST"])
def admin_reissue_certificate(request, user_id):
    """
    Admin-only: Force re-issue a certificate for any user.
    
    This bypasses the normal renewal restrictions and creates a new certificate
    immediately, revoking any existing active certificates.
    
    SECURITY: Requires admin privileges. All actions are logged.
    """
    if not request.user.is_staff:
        logger.warning(f"Non-admin user {request.user.username} attempted to use admin_reissue_certificate")
        return JsonResponse({'error': 'Admin access required'}, status=403)
    
    from signing.certificate_issuer import issue_user_certificate
    
    try:
        target_user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)
    
    reason = request.POST.get('reason', 'admin_reissue')
    notes = request.POST.get('notes', '')
    
    # Get and revoke all active certificates for this user
    active_certs = UserCert.objects.filter(user=target_user, active=True)
    revoked_count = 0
    for cert in active_certs:
        cert.revoke(reason='superseded', revoked_by=request.user)
        CertificateRevocationLog.objects.create(
            certificate=cert,
            revoked_by=request.user,
            reason=f'superseded (admin reissue: {reason})',
            notes=notes
        )
        revoked_count += 1
    
    # Get the common name from old cert or generate new one
    old_cert = active_certs.first()
    common_name = old_cert.common_name if old_cert else target_user.username
    
    # Issue new certificate
    result = issue_user_certificate(target_user.username, common_name=common_name)
    
    if not result.get('ok'):
        logger.error(f"Admin reissue failed for {target_user.username}: {result.get('error')}")
        return JsonResponse({'error': 'Certificate re-issue failed'}, status=500)
    
    # Create new certificate record
    new_cert = UserCert.objects.create(
        user=target_user,
        common_name=common_name,
        serial_number=result.get('serial_number', ''),
        p12_enc_path=result.get('p12_enc_path', ''),
        p12_pass_enc_path=result.get('p12_pass_enc_path', ''),
        valid_from=result.get('valid_from'),
        expires_at=result.get('expires_at')
    )
    
    logger.info(f"Admin {request.user.username} reissued certificate for user: {target_user.username}, reason: {reason}")
    
    return JsonResponse({
        'ok': True,
        'message': f'Certificate reissued successfully for {target_user.username}',
        'new_cert_id': new_cert.id,
        'revoked_count': revoked_count,
        'admin_user': request.user.username
    })


@login_required
@require_http_methods(["POST"])
def admin_force_renew(request, cert_id):
    """
    Admin-only: Force renewal of a specific certificate regardless of expiry status.
    
    SECURITY: Requires admin privileges. All actions are logged.
    """
    if not request.user.is_staff:
        logger.warning(f"Non-admin user {request.user.username} attempted to use admin_force_renew")
        return JsonResponse({'error': 'Admin access required'}, status=403)
    
    from signing.certificate_issuer import issue_user_certificate
    
    try:
        old_cert = UserCert.objects.get(id=cert_id)
    except UserCert.DoesNotExist:
        return JsonResponse({'error': 'Certificate not found'}, status=404)
    
    target_user = old_cert.user
    reason = request.POST.get('reason', 'admin_forced_renewal')
    notes = request.POST.get('notes', '')
    
    # Issue new certificate
    result = issue_user_certificate(target_user.username, common_name=old_cert.common_name)
    
    if not result.get('ok'):
        logger.error(f"Admin forced renewal failed for {target_user.username}: {result.get('error')}")
        return JsonResponse({'error': 'Certificate renewal failed'}, status=500)
    
    # Revoke old certificate
    if old_cert.active:
        old_cert.revoke(reason='superseded', revoked_by=request.user)
        CertificateRevocationLog.objects.create(
            certificate=old_cert,
            revoked_by=request.user,
            reason=f'superseded (admin forced renewal: {reason})',
            notes=notes
        )
    
    # Create new certificate record
    new_cert = UserCert.objects.create(
        user=target_user,
        common_name=old_cert.common_name,
        serial_number=result.get('serial_number', ''),
        p12_enc_path=result.get('p12_enc_path', ''),
        p12_pass_enc_path=result.get('p12_pass_enc_path', ''),
        valid_from=result.get('valid_from'),
        expires_at=result.get('expires_at')
    )
    
    logger.info(f"Admin {request.user.username} force renewed certificate {cert_id} for user: {target_user.username}")
    
    return JsonResponse({
        'ok': True,
        'message': f'Certificate renewed successfully for {target_user.username}',
        'new_cert_id': new_cert.id,
        'old_cert_id': cert_id,
        'old_cert_revoked': True,
        'admin_user': request.user.username
    })


@login_required
def admin_list_all_certificates(request):
    """
    Admin-only: List all certificates in the system with detailed status.
    
    SECURITY: Requires admin privileges.
    """
    if not request.user.is_staff:
        return JsonResponse({'error': 'Admin access required'}, status=403)
    
    now = timezone.now()
    certs = UserCert.objects.select_related('user').order_by('-created_at')
    
    # Optional filters
    status_filter = request.GET.get('status')
    user_filter = request.GET.get('username')
    
    if user_filter:
        certs = certs.filter(user__username__icontains=user_filter)
    
    result = []
    for cert in certs:
        # Calculate status
        if not cert.active:
            status = 'revoked'
        elif cert.expires_at and cert.expires_at < now:
            status = 'expired'
        elif cert.expires_at:
            days_remaining = (cert.expires_at - now).days
            if days_remaining <= 30:
                status = 'expiring_soon'
            else:
                status = 'valid'
        else:
            status = 'valid'
        
        # Apply status filter
        if status_filter and status != status_filter:
            continue
        
        result.append({
            'id': cert.id,
            'username': cert.user.username,
            'common_name': cert.common_name,
            'serial_number': cert.serial_number,
            'status': status,
            'active': cert.active,
            'created_at': cert.created_at.isoformat(),
            'valid_from': cert.valid_from.isoformat() if cert.valid_from else None,
            'expires_at': cert.expires_at.isoformat() if cert.expires_at else None,
            'days_remaining': (cert.expires_at - now).days if cert.expires_at and cert.active else None,
            'revoked_at': cert.revoked_at.isoformat() if cert.revoked_at else None,
            'revocation_reason': cert.revocation_reason
        })
    
    return JsonResponse({
        'certificates': result,
        'total_count': len(result)
    })

