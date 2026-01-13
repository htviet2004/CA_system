
import hashlib
import base64
import os
import shutil
from django.conf import settings
from cryptography.fernet import Fernet


def derive_encryption_key():
    
    digest = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
    return base64.urlsafe_b64encode(digest)


def get_fernet():
    
    return Fernet(derive_encryption_key())


def find_pyhanko_executable(preferred=None):
    
    if preferred and os.path.basename(preferred) == preferred:
        p = shutil.which(preferred)
        if p:
            return p

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

    candidates.append(os.path.join(base, '..', 'env', 'Scripts', 'pyhanko.exe'))
    candidates.append(os.path.join(base, '..', 'env', 'Scripts', 'pyhanko'))

    for c in candidates:
        if c and os.path.exists(c):
            return c

    path = shutil.which('pyhanko')
    if path:
        return path
    return None
