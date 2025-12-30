import os
import hashlib
import base64
from pathlib import Path
from django.conf import settings
from django.http import JsonResponse, FileResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate
from .models import UserCert
from cryptography.fernet import Fernet
import subprocess
import tempfile
from django.contrib.auth.models import User


def _derive_key():
    digest = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
    return base64.urlsafe_b64encode(digest)


@csrf_exempt
def list_certs(request):
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'auth required'}, status=401)
    if request.user.is_staff:
        qs = UserCert.objects.all()
    else:
        qs = UserCert.objects.filter(user=request.user)
    out = []
    for c in qs:
        out.append({'id': c.id, 'user': c.user.username, 'cn': c.common_name, 'created_at': c.created_at.isoformat(), 'active': c.active})
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
    # save uploaded p12
    with open(p12_path, 'wb') as fh:
        for chunk in uploaded.chunks():
            fh.write(chunk)

    # encrypt p12 and passphrase
    f = Fernet(_derive_key())
    enc = f.encrypt(p12_path.read_bytes())
    p12_enc_path = user_dir / 'user.p12.enc'
    p12_enc_path.write_bytes(enc)
    pass_enc_path = user_dir / 'p12.pass.enc'
    pass_text = passphrase or ''
    pass_enc_path.write_bytes(f.encrypt(pass_text.encode('utf-8')))

    # record in DB
    uc = UserCert.objects.create(user=user, common_name=username, p12_enc_path=str(p12_enc_path), p12_pass_enc_path=str(pass_enc_path))
    return JsonResponse({'ok': True, 'id': uc.id})


@csrf_exempt
def issue_cert(request):
    """Issue certificate for a user, sign with intermediate CA, store encrypted PKCS#12 and record it."""
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
    # find intermediate CA cert/key
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
        # fallback search
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

        # include extensions if present
        extfile = user_dir / 'v3_ext.cnf'
        if extfile.exists():
            subprocess.run([
                'openssl', 'x509', '-req', '-in', str(csr_path), '-CA', str(interm_cert), '-CAkey', str(interm_key),
                '-CAcreateserial', '-out', str(crt_path), '-days', '365', '-sha256', '-extfile', str(extfile), '-extensions', 'v3_req'
            ], check=True)
        else:
            subprocess.run(['openssl', 'x509', '-req', '-in', str(csr_path), '-CA', str(interm_cert), '-CAkey', str(interm_key), '-CAcreateserial', '-out', str(crt_path), '-days', '365', '-sha256'], check=True)

        subprocess.run(['openssl', 'pkcs12', '-export', '-inkey', str(key_path), '-in', str(crt_path), '-certfile', str(interm_cert), '-out', str(p12_path), '-passout', f'pass:{passphrase}'], check=True)

        # encrypt and store
        f = Fernet(_derive_key())
        enc = f.encrypt(p12_path.read_bytes())
        p12_enc_path = user_dir / 'user.p12.enc'
        p12_enc_path.write_bytes(enc)
        pass_enc_path = user_dir / 'p12.pass.enc'
        pass_enc_path.write_bytes(f.encrypt(passphrase.encode('utf-8')))

        # DB record
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
    if request.method != 'POST':
        return JsonResponse({'error': 'POST only'}, status=405)
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'auth required'}, status=401)
    try:
        uc = UserCert.objects.get(pk=pk)
    except UserCert.DoesNotExist:
        return JsonResponse({'error': 'not found'}, status=404)
    if uc.user != request.user and not request.user.is_staff:
        return JsonResponse({'error': 'forbidden'}, status=403)
    uc.active = False
    uc.save()
    return JsonResponse({'ok': True})
