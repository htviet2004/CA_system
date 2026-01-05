from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.conf import settings
from django.contrib.auth import authenticate
import os
from signing.utils import get_fernet


def _derive_key():
    """DEPRECATED: Use signing.utils.derive_encryption_key() instead"""
    from signing.utils import derive_encryption_key
    return derive_encryption_key()


@csrf_exempt
def upload_p12(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'POST only'}, status=405)

    username = request.POST.get('username')
    password = request.POST.get('password')
    if not username or not password:
        return JsonResponse({'error': 'username & password required'}, status=400)
    user = authenticate(username=username, password=password)
    if not user:
        return JsonResponse({'error': 'authentication failed'}, status=401)

    p12_file = request.FILES.get('p12')
    passphrase = request.POST.get('passphrase', '')
    if not p12_file:
        return JsonResponse({'error': 'p12 file required'}, status=400)

    user_dir = os.path.join(settings.BASE_DIR, 'users', username)
    os.makedirs(user_dir, exist_ok=True)

    # encrypt and store
    f = get_fernet()
    enc_p12 = f.encrypt(p12_file.read())
    with open(os.path.join(user_dir, 'user.p12.enc'), 'wb') as fh:
        fh.write(enc_p12)
    enc_pass = f.encrypt(passphrase.encode('utf-8'))
    with open(os.path.join(user_dir, 'p12.pass.enc'), 'wb') as fh:
        fh.write(enc_pass)

    return JsonResponse({'ok': True})
