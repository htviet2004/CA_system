import os
import subprocess
import tempfile
import hashlib
import base64
from django.conf import settings
from django.http import JsonResponse, FileResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate
from cryptography.fernet import Fernet
import traceback
import sys
import time
import shutil
import json
from usercerts.models import UserCert


def _find_pyhanko(preferred=None):
    # If preferred is a simple command name, prefer PATH lookup
    if preferred and os.path.basename(preferred) == preferred:
        p = shutil.which(preferred)
        if p:
            return p

    # If preferred is an absolute/relative path and exists, use it
    if preferred:
        try:
            if os.path.exists(preferred):
                return preferred
        except Exception:
            pass

    base = getattr(settings, 'BASE_DIR', os.getcwd())
    candidates = []
    for venv_name in ('.venv', 'venv', 'env'):
        candidates.append(os.path.join(base, venv_name, 'Scripts', 'pyhanko.exe'))
        candidates.append(os.path.join(base, venv_name, 'Scripts', 'pyhanko'))

    # Also check a top-level env folder (one level up)
    candidates.append(os.path.join(base, '..', 'env', 'Scripts', 'pyhanko.exe'))
    candidates.append(os.path.join(base, '..', 'env', 'Scripts', 'pyhanko'))

    for c in candidates:
        if c and os.path.exists(c):
            return c

    # fallback to PATH
    path = shutil.which('pyhanko')
    if path:
        return path
    return None


@csrf_exempt
def sign_file(request):
    try:
        # handle CORS preflight requests from the browser
        if request.method == 'OPTIONS':
            return JsonResponse({'ok': True})

        if request.method != 'POST':
            return JsonResponse({'error': 'POST only'}, status=405)

        uploaded = request.FILES.get('file')
        if not uploaded:
            return JsonResponse({'error': 'no file uploaded'}, status=400)

        reason = request.POST.get('reason', 'Signed')
        location = request.POST.get('location', '')
        field = request.POST.get('field', '1/10,10,190,60/Sig1')
        # prefer session-based auth; fall back to username/password in POST
        username = None
        user = None
        if hasattr(request, 'user') and request.user.is_authenticated:
            user = request.user
            username = user.username
        else:
            username = request.POST.get('username')
            password = request.POST.get('password')
            if username and password:
                user = authenticate(username=username, password=password)
                if not user:
                    return JsonResponse({'error': 'authentication failed'}, status=401)

        if user:
            # prefer UserCert from DB if available
            uc = UserCert.objects.filter(user=user, active=True).order_by('-created_at').first()
            enc_p12 = None
            enc_pass = None
            if uc:
                # stored paths may be relative to BASE_DIR
                p = uc.p12_enc_path or ''
                pp = uc.p12_pass_enc_path or ''
                if p and not os.path.isabs(p):
                    p = os.path.join(settings.BASE_DIR, p)
                if pp and not os.path.isabs(pp):
                    pp = os.path.join(settings.BASE_DIR, pp)
                if os.path.exists(p) and os.path.exists(pp):
                    enc_p12 = p
                    enc_pass = pp

            # fallback to user directory files if no DB cert
            user_dir = os.path.join(settings.BASE_DIR, 'users', username)
            if not enc_p12 or not enc_pass:
                fs_p12 = os.path.join(user_dir, 'user.p12.enc')
                fs_pass = os.path.join(user_dir, 'p12.pass.enc')
                if os.path.exists(fs_p12) and os.path.exists(fs_pass):
                    enc_p12 = fs_p12
                    enc_pass = fs_pass

            if not enc_p12 or not enc_pass:
                # try auto-issuing a cert for the user (MVP convenience)
                try:
                    script = os.path.join(settings.BASE_DIR, 'scripts', 'issue_cert.py')
                    # prefer explicit p12.pass if provided in plain file
                    plain_pass_file = os.path.join(user_dir, 'p12.pass')
                    if os.path.exists(plain_pass_file):
                        passphrase = open(plain_pass_file, 'r', encoding='utf-8').read().strip()
                    else:
                        # fall back to provided POST password or a default
                        passphrase = request.POST.get('password') or 'changeit'
                    proc = subprocess.run([sys.executable, script, username, passphrase], capture_output=True, text=True)
                    # give filesystem a moment
                    time.sleep(0.2)
                    # try to parse JSON output if present
                    out = proc.stdout or ''
                    jidx = out.rfind('{')
                    parsed = None
                    if jidx != -1:
                        try:
                            parsed = json.loads(out[jidx:])
                        except Exception:
                            parsed = None
                    if parsed and parsed.get('ok'):
                        ep = parsed.get('p12_enc_path')
                        pp = parsed.get('p12_pass_enc_path')
                        if ep and not os.path.isabs(ep):
                            ep = os.path.join(settings.BASE_DIR, ep)
                        if pp and not os.path.isabs(pp):
                            pp = os.path.join(settings.BASE_DIR, pp)
                        if ep and pp and os.path.exists(ep) and os.path.exists(pp):
                            enc_p12 = ep
                            enc_pass = pp
                except Exception as e:
                    return JsonResponse({'error': 'user p12 not found; auto-issue failed', 'detail': str(e)}, status=500)

            if not enc_p12 or not enc_pass:
                return JsonResponse({'error': 'no user certificate available'}, status=400)

            # decrypt to temp files
            def _derive_key():
                digest = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
                return base64.urlsafe_b64encode(digest)

            f = Fernet(_derive_key())
            with open(enc_p12, 'rb') as fh:
                p12_data = f.decrypt(fh.read())
            with open(enc_pass, 'rb') as fh:
                pass_data = f.decrypt(fh.read()).decode('utf-8')

            in_tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
            try:
                for chunk in uploaded.chunks():
                    in_tmp.write(chunk)
                in_tmp.flush()
                in_path = in_tmp.name
            finally:
                in_tmp.close()

            out_fd, out_path = tempfile.mkstemp(suffix='.pdf')
            os.close(out_fd)

            # write p12 and passphrase to temp files
            p12_tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.p12')
            p12_tmp.write(p12_data)
            p12_tmp.flush()
            p12_tmp.close()
            pass_tmp = tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.txt')
            pass_tmp.write(pass_data)
            pass_tmp.flush()
            pass_tmp.close()

            pyhanko_pref = getattr(settings, 'PYHANKO_CLI', 'pyhanko')
            pyhanko = _find_pyhanko(pyhanko_pref)
            if pyhanko is None:
                return JsonResponse({'error': 'pyhanko CLI not found', 'details': f"Tried '{pyhanko_pref}' and common venv locations but pyhanko not found. Install pyHanko CLI in the project's venv or set settings.PYHANKO_CLI to its full path."}, status=500)

            cmd = [sys.executable, '-m', 'pyhanko', 'sign', 'addsig', '--field', field, '--reason', reason, '--location', location, 'pkcs12', '--passfile', pass_tmp.name, in_path, out_path, p12_tmp.name]
            try:
                proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            except FileNotFoundError as e:
                return JsonResponse({'error': 'pyhanko execution failed', 'details': str(e)}, status=500)

            # cleanup temp p12 & pass
            try:
                os.unlink(p12_tmp.name)
                os.unlink(pass_tmp.name)
            except Exception:
                pass

            if proc.returncode != 0:
                try:
                    os.unlink(in_path)
                    os.unlink(out_path)
                except Exception:
                    pass
                extra = {}
                try:
                    ver = subprocess.run([pyhanko, '--version'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                    extra['pyhanko_version_check'] = {'returncode': ver.returncode, 'output': ver.stdout}
                except Exception as e:
                    extra['pyhanko_version_check'] = {'error': str(e)}
                extra['env'] = {'sys_executable': sys.executable, 'PATH': os.environ.get('PATH')}
                return JsonResponse({'error': 'signing failed', 'cmd': cmd, 'returncode': proc.returncode, 'output': proc.stdout, **extra}, status=500)

            resp = FileResponse(open(out_path, 'rb'), as_attachment=True, filename=(uploaded.name or 'signed.pdf'))
            try:
                os.unlink(in_path)
            except Exception:
                pass
            return resp

        # fallback: use default signer from settings
        # write uploaded PDF to temp file
        in_tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
        try:
            for chunk in uploaded.chunks():
                in_tmp.write(chunk)
            in_tmp.flush()
            in_path = in_tmp.name
        finally:
            in_tmp.close()

        out_fd, out_path = tempfile.mkstemp(suffix='.pdf')
        os.close(out_fd)

        pyhanko_pref = getattr(settings, 'PYHANKO_CLI', 'pyhanko')
        pyhanko = _find_pyhanko(pyhanko_pref)
        if pyhanko is None:
            return JsonResponse({'error': 'pyhanko CLI not found', 'details': f"Tried '{pyhanko_pref}' and common venv locations but pyhanko not found. Install pyHanko CLI in the project's venv or set settings.PYHANKO_CLI to its full path."}, status=500)
        p12 = getattr(settings, 'DEFAULT_SIGNER_P12', None)
        passfile = getattr(settings, 'DEFAULT_SIGNER_P12_PASSFILE', None)
        if not p12 or not passfile:
            return JsonResponse({'error': 'signer not configured'}, status=500)

        cmd = [sys.executable, '-m', 'pyhanko', 'sign', 'addsig', '--field', field, '--reason', reason, '--location', location, 'pkcs12', '--passfile', passfile, in_path, out_path, p12]

        try:
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        except FileNotFoundError as e:
            return JsonResponse({'error': 'pyhanko execution failed', 'details': str(e)}, status=500)
        if proc.returncode != 0:
            # cleanup
            try:
                os.unlink(in_path)
                os.unlink(out_path)
            except Exception:
                pass
            extra = {}
            try:
                ver = subprocess.run([pyhanko, '--version'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                extra['pyhanko_version_check'] = {'returncode': ver.returncode, 'output': ver.stdout}
            except Exception as e:
                extra['pyhanko_version_check'] = {'error': str(e)}
            extra['env'] = {'sys_executable': sys.executable, 'PATH': os.environ.get('PATH')}
            return JsonResponse({'error': 'signing failed', 'cmd': cmd, 'returncode': proc.returncode, 'output': proc.stdout, **extra}, status=500)

        # stream signed file back
        resp = FileResponse(open(out_path, 'rb'), as_attachment=True, filename=(uploaded.name or 'signed.pdf'))

        # cleanup temp input file; keep output for download streaming
        try:
            os.unlink(in_path)
        except Exception:
            pass

        return resp
    except Exception as exc:
        tb = traceback.format_exc()
        return JsonResponse({'error': 'internal server error', 'detail': str(exc), 'traceback': tb}, status=500)
