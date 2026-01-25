"""
P12 certificate upload handling.

SECURITY: Validates and encrypts uploaded certificates.
"""

import os
import logging

from django.http import JsonResponse
from django.conf import settings
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required

from signing.utils import get_fernet
from signing.validators import validate_p12_upload

logger = logging.getLogger(__name__)


@csrf_exempt  # TODO: Re-enable CSRF for production
@login_required
@require_http_methods(["POST"])
def upload_p12(request):
    """
    Upload a PKCS#12 certificate file.
    
    NOTE: CSRF temporarily disabled for testing.
    Validates file, encrypts before storage.
    """
    p12_file = request.FILES.get('p12')
    passphrase = request.POST.get('passphrase', '')
    
    # SECURITY: Validate uploaded file
    try:
        validate_p12_upload(p12_file)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)
    
    user = request.user
    username = user.username

    user_dir = os.path.join(settings.BASE_DIR, 'users', username)
    os.makedirs(user_dir, exist_ok=True)

    f = get_fernet()
    enc_p12 = f.encrypt(p12_file.read())
    with open(os.path.join(user_dir, 'user.p12.enc'), 'wb') as fh:
        fh.write(enc_p12)
    enc_pass = f.encrypt(passphrase.encode('utf-8'))
    with open(os.path.join(user_dir, 'p12.pass.enc'), 'wb') as fh:
        fh.write(enc_pass)
    
    logger.info(f"P12 uploaded for user: {username}")
    return JsonResponse({'ok': True})
