import os
from pathlib import Path
from django.conf import settings
from django.http import JsonResponse, FileResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.utils import timezone
from .models import UserCert, SigningHistory, CertificateRevocationLog
import subprocess
import tempfile
from signing.utils import get_fernet


def _derive_key():
    from signing.utils import derive_encryption_key
    return derive_encryption_key()


def _is_admin(request):
    """Check if request user is authenticated admin."""
    return request.user.is_authenticated and request.user.is_staff


@csrf_exempt
def list_certs(request):
    """List certificates - all for admin, own for users."""
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'auth required'}, status=401)
    
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


@csrf_exempt
def upload_p12(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'POST only'}, status=405)
    username = request.POST.get('username')
    password = request.POST.get('password')
    passphrase = request.POST.get('passphrase', '')
    user = authenticate(username=username, password=password)
    if not user:
        return JsonResponse({'error': 'authentication failed'}, status=401)
    uploaded = request.FILES.get('file')
    if not uploaded:
        return JsonResponse({'error': 'no file uploaded'}, status=400)

    user_dir = Path(settings.BASE_DIR) / 'users' / username
    os.makedirs(user_dir, exist_ok=True)
    p12_path = user_dir / f'{username}.p12'
    with open(p12_path, 'wb') as fh:
        for chunk in uploaded.chunks():
            fh.write(chunk)

    f = get_fernet()
    enc = f.encrypt(p12_path.read_bytes())
    p12_enc_path = user_dir / 'user.p12.enc'
    p12_enc_path.write_bytes(enc)
    pass_enc_path = user_dir / 'p12.pass.enc'
    pass_text = passphrase or ''
    pass_enc_path.write_bytes(f.encrypt(pass_text.encode('utf-8')))

    uc = UserCert.objects.create(user=user, common_name=username, p12_enc_path=str(p12_enc_path), p12_pass_enc_path=str(pass_enc_path))
    return JsonResponse({'ok': True, 'id': uc.id})


@csrf_exempt
def issue_cert(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'POST only'}, status=405)
    username = request.POST.get('username')
    password = request.POST.get('password')
    passphrase = request.POST.get('passphrase', 'changeit')
    cn = request.POST.get('cn', username)

    user = authenticate(username=username, password=password)
    if not user:
        return JsonResponse({'error': 'authentication failed'}, status=401)

    user_dir = Path(settings.BASE_DIR) / 'users' / username
    os.makedirs(user_dir, exist_ok=True)

    project_root = Path(settings.BASE_DIR)
    def find_intermediate(root: Path):
        candidates = [root / 'CA' / 'intermediate-ca', root / 'certs' / 'intermediate-ca', root / 'certs']
        for c in candidates:
            cert1 = c / 'certs' / 'intermediate.crt'
            cert2 = c / 'intermediate.crt'
            cert3 = c / 'intermediateCA.crt'
            key = c / 'private' / 'intermediate.key'
            if cert1.exists() and key.exists():
                return cert1, key
            if cert2.exists() and key.exists():
                return cert2, key
            if cert3.exists() and key.exists():
                return cert3, key
        cert_found = None
        key_found = None
        for p in root.rglob('intermediate*.crt'):
            cert_found = p
            break
        for p in root.rglob('intermediate*.key'):
            key_found = p
            break
        return cert_found, key_found

    interm_cert, interm_key = find_intermediate(project_root)
    if not interm_cert or not interm_key or not interm_key.exists():
        return JsonResponse({'error': 'intermediate CA cert/key not found on server'}, status=500)

    key_path = user_dir / f'{username}.key'
    csr_path = user_dir / f'{username}.csr'
    crt_path = user_dir / f'{username}.crt'
    p12_path = user_dir / f'{username}.p12'

    try:
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', str(key_path)], check=True)
        subj = f"/CN={cn}/emailAddress={username}@dut.local"
        subprocess.run(['openssl', 'req', '-new', '-key', str(key_path), '-subj', subj, '-out', str(csr_path)], check=True)

        extfile = user_dir / 'v3_ext.cnf'
        if extfile.exists():
            subprocess.run([
                'openssl', 'x509', '-req', '-in', str(csr_path), '-CA', str(interm_cert), '-CAkey', str(interm_key),
                '-CAcreateserial', '-out', str(crt_path), '-days', '365', '-sha256', '-extfile', str(extfile), '-extensions', 'v3_req'
            ], check=True)
        else:
            subprocess.run(['openssl', 'x509', '-req', '-in', str(csr_path), '-CA', str(interm_cert), '-CAkey', str(interm_key), '-CAcreateserial', '-out', str(crt_path), '-days', '365', '-sha256'], check=True)

        subprocess.run(['openssl', 'pkcs12', '-export', '-inkey', str(key_path), '-in', str(crt_path), '-certfile', str(interm_cert), '-out', str(p12_path), '-passout', f'pass:{passphrase}'], check=True)

        f = get_fernet()
        enc = f.encrypt(p12_path.read_bytes())
        p12_enc_path = user_dir / 'user.p12.enc'
        p12_enc_path.write_bytes(enc)
        pass_enc_path = user_dir / 'p12.pass.enc'
        pass_enc_path.write_bytes(f.encrypt(passphrase.encode('utf-8')))

        uc = UserCert.objects.create(user=user, common_name=cn, p12_enc_path=str(p12_enc_path), p12_pass_enc_path=str(pass_enc_path))
    except subprocess.CalledProcessError as e:
        return JsonResponse({'error': 'openssl failed', 'detail': str(e)}, status=500)

    return JsonResponse({'ok': True, 'id': uc.id, 'p12': str(p12_path)})


@csrf_exempt
def download_p12(request, pk):
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'auth required'}, status=401)
    try:
        uc = UserCert.objects.get(pk=pk)
    except UserCert.DoesNotExist:
        return JsonResponse({'error': 'not found'}, status=404)
    if uc.user != request.user and not request.user.is_staff:
        return JsonResponse({'error': 'forbidden'}, status=403)
    return FileResponse(open(uc.p12_enc_path, 'rb'), as_attachment=True, filename=os.path.basename(uc.p12_enc_path))


@csrf_exempt
def revoke_cert(request, pk):
    """
    Revoke a certificate (admin only or own certificate).
    Also revokes all signatures made with this certificate.
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'POST only'}, status=405)
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'auth required'}, status=401)
    
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

@csrf_exempt
def list_signing_history(request):
    """
    List signing history.
    Admin: all records
    User: own records only
    """
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'auth required'}, status=401)
    
    if request.user.is_staff:
        qs = SigningHistory.objects.all()
    else:
        qs = SigningHistory.objects.filter(user=request.user)
    
    qs = qs.select_related('user', 'certificate', 'revoked_by').order_by('-signed_at')
    
    # Pagination
    limit = int(request.GET.get('limit', 50))
    offset = int(request.GET.get('offset', 0))
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


@csrf_exempt
def signing_history_by_user(request, username):
    """Get signing history for a specific user."""
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'auth required'}, status=401)
    
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


@csrf_exempt
def signing_history_by_document(request, doc_hash):
    """
    Get signing history for a specific document (by hash).
    Useful for verifying document authenticity.
    """
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'auth required'}, status=401)
    
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


@csrf_exempt
def revoke_signature(request, pk):
    """
    Revoke a specific signature (admin only).
    Does not revoke the certificate, only this signature.
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'POST only'}, status=405)
    
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

@csrf_exempt
def revocation_log(request):
    """
    Get revocation log (admin only).
    Shows all certificate revocations for audit.
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


@csrf_exempt
def check_revocation_status(request, serial_or_hash):
    """
    Check if a certificate (by serial) or signature (by doc hash) is revoked.
    Public endpoint for verification integration.
    """
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
    signatures = SigningHistory.objects.filter(document_hash=serial_or_hash)
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
