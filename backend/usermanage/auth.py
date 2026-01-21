import os
import subprocess
import tempfile
import sys
import json
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from usercerts.models import UserCert
from signing.utils import get_fernet, derive_encryption_key


def _derive_key():
    return derive_encryption_key()


@csrf_exempt
def register(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'POST only'}, status=405)
    username = request.POST.get('username')
    password = request.POST.get('password')
    full_name = request.POST.get('full_name', '')
    if not username or not password:
        return JsonResponse({'error': 'username and password required'}, status=400)
    if User.objects.filter(username=username).exists():
        return JsonResponse({'error': 'user exists'}, status=400)
    user = User.objects.create_user(username=username, password=password)
    if full_name:
        user.first_name = full_name
        user.save()
    issued = False
    issue_output = ''
    try:
        script = os.path.join(settings.BASE_DIR, 'scripts', 'issue_cert.py')
        proc = subprocess.run([sys.executable, str(script), username, password], capture_output=True, text=True)
        issue_output = (proc.stdout or '') + (proc.stderr or '')
        parsed = None
        out = proc.stdout or ''
        jidx = out.rfind('{')
        if jidx != -1:
            try:
                parsed = json.loads(out[jidx:])
            except Exception:
                parsed = None
        else:
            try:
                parsed = json.loads(out)
            except Exception:
                parsed = None

        issued = False
        if parsed and parsed.get('ok'):
            issued = True
            try:
                p12_enc = parsed.get('p12_enc_path')
                pass_enc = parsed.get('p12_pass_enc_path')
                if p12_enc and p12_enc.startswith(settings.BASE_DIR):
                    p12_rel = os.path.relpath(p12_enc, settings.BASE_DIR)
                else:
                    p12_rel = p12_enc
                if pass_enc and pass_enc.startswith(settings.BASE_DIR):
                    pass_rel = os.path.relpath(pass_enc, settings.BASE_DIR)
                else:
                    pass_rel = pass_enc
                UserCert.objects.create(user=user, common_name=username, p12_enc_path=p12_rel or '', p12_pass_enc_path=pass_rel or '', active=True)
            except Exception:
                pass
    except Exception as e:
        issue_output = str(e)

    return JsonResponse({'ok': True, 'username': username, 'cert_issued': issued, 'issue_output': issue_output})


@csrf_exempt
def login_view(request):
    """
    Authenticate user and create Django session.
    Session cookie is HttpOnly and persists across page reloads.
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'POST only'}, status=405)
    username = request.POST.get('username')
    password = request.POST.get('password')
    user = authenticate(username=username, password=password)
    if not user:
        return JsonResponse({'error': 'invalid credentials'}, status=401)
    login(request, user)
    return JsonResponse({
        'ok': True, 
        'username': username,
        'is_staff': user.is_staff,
        'is_active': user.is_active
    })


@csrf_exempt
def issue_cert(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'POST only'}, status=405)
    username = request.POST.get('username')
    password = request.POST.get('password')
    common_name = request.POST.get('cn', username)
    passphrase = request.POST.get('passphrase', 'changeit')

    user = authenticate(username=username, password=password)
    if not user:
        return JsonResponse({'error': 'authentication failed'}, status=401)

    user_dir = os.path.join(settings.BASE_DIR, 'users', username)
    os.makedirs(user_dir, exist_ok=True)

    project_root = settings.BASE_DIR
    def _find_intermediate():
        candidates = [
            os.path.join(project_root, 'CA', 'intermediate-ca'),
            os.path.join(project_root, 'certs', 'intermediate-ca'),
            os.path.join(project_root, 'certs'),
        ]
        for c in candidates:
            cert1 = os.path.join(c, 'certs', 'intermediate.crt')
            cert2 = os.path.join(c, 'intermediate.crt')
            cert3 = os.path.join(c, 'intermediateCA.crt')
            key = os.path.join(c, 'private', 'intermediate.key')
            if os.path.exists(cert1) and os.path.exists(key):
                return cert1, key
            if os.path.exists(cert2) and os.path.exists(key):
                return cert2, key
            if os.path.exists(cert3) and os.path.exists(key):
                return cert3, key
        cert_found = None
        key_found = None
        for root, dirs, files in os.walk(project_root):
            for f in files:
                if f.lower().startswith('intermediate') and f.lower().endswith('.crt'):
                    cert_found = os.path.join(root, f)
                if f.lower().startswith('intermediate') and f.lower().endswith('.key'):
                    key_found = os.path.join(root, f)
                if cert_found and key_found:
                    return cert_found, key_found
        return cert_found, key_found

    interm_cert, interm_key = _find_intermediate()
    if not interm_cert or not interm_key or not os.path.exists(interm_key):
        raise RuntimeError(f'Intermediate CA cert/key not found. cert={interm_cert} key={interm_key}')

    key_path = os.path.join(user_dir, f'{username}.key')
    csr_path = os.path.join(user_dir, f'{username}.csr')
    crt_path = os.path.join(user_dir, f'{username}.crt')
    p12_path = os.path.join(user_dir, f'{username}.p12')

    subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', key_path], check=True)
    subj = f"/CN={common_name}/emailAddress={username}@dut.local"
    subprocess.run(['openssl', 'req', '-new', '-key', key_path, '-subj', subj, '-out', csr_path], check=True)
    extfile = os.path.join(user_dir, 'v3_ext.cnf')
    if os.path.exists(extfile):
        subprocess.run(['openssl', 'x509', '-req', '-in', csr_path, '-CA', interm_cert, '-CAkey', interm_key, '-CAcreateserial', '-out', crt_path, '-days', '365', '-sha256', '-extfile', extfile, '-extensions', 'v3_req'], check=True)
    else:
        subprocess.run(['openssl', 'x509', '-req', '-in', csr_path, '-CA', interm_cert, '-CAkey', interm_key, '-CAcreateserial', '-out', crt_path, '-days', '365', '-sha256'], check=True)
    subprocess.run(['openssl', 'pkcs12', '-export', '-inkey', key_path, '-in', crt_path, '-certfile', interm_cert, '-out', p12_path, '-passout', f'pass:{passphrase}'], check=True)

    f = get_fernet()
    with open(p12_path, 'rb') as fh:
        enc = f.encrypt(fh.read())
    with open(os.path.join(user_dir, 'user.p12.enc'), 'wb') as fh:
        fh.write(enc)
    with open(os.path.join(user_dir, 'p12.pass.enc'), 'wb') as fh:
        fh.write(f.encrypt(passphrase.encode('utf-8')))

    try:
        p12_enc_rel = os.path.join('users', username, 'user.p12.enc')
        pass_enc_rel = os.path.join('users', username, 'p12.pass.enc')
        uc = UserCert.objects.create(
            user=user,
            common_name=common_name,
            p12_enc_path=p12_enc_rel,
            p12_pass_enc_path=pass_enc_rel,
            active=True,
        )
    except Exception:
        uc = None

    resp = {'ok': True, 'p12': p12_path}
    if uc:
        resp['usercert_id'] = uc.id
    return JsonResponse(resp)


@csrf_exempt
def verify(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'POST only'}, status=405)
    uploaded = request.FILES.get('file')
    if not uploaded:
        return JsonResponse({'error': 'no file uploaded'}, status=400)
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
    try:
        for chunk in uploaded.chunks():
            tmp.write(chunk)
        tmp.flush()
        tmp_path = tmp.name
    finally:
        tmp.close()

    pyhanko = getattr(settings, 'PYHANKO_CLI', 'pyhanko')
    rootca = os.path.join(settings.BASE_DIR, 'certs', 'rootCA.crt')
    cmd = [pyhanko, 'sign', 'validate', tmp_path, '--trust', rootca]


@csrf_exempt
def get_current_user(request):
    """
    Return currently authenticated user info from Django session.
    Used to restore user state after page reload.
    """
    if not request.user.is_authenticated:
        return JsonResponse({'authenticated': False}, status=200)
    
    return JsonResponse({
        'authenticated': True,
        'username': request.user.username,
        'is_staff': request.user.is_staff,
        'is_active': request.user.is_active,
        'email': request.user.email or ''
    })


@csrf_exempt
def logout_view(request):
    """
    Logout user and destroy Django session.
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'POST only'}, status=405)
    
    logout(request)
    return JsonResponse({'ok': True, 'message': 'Logged out successfully'})
    proc = subprocess.run(cmd, capture_output=True, text=True)
    try:
        os.unlink(tmp_path)
    except Exception:
        pass
    if proc.returncode != 0:
        return JsonResponse({'ok': False, 'output': proc.stderr}, status=200)
    return JsonResponse({'ok': True, 'output': proc.stdout}, status=200)
