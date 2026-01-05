"""
Utility functions for signing module
"""
import hashlib
import base64
import os
import shutil
from django.conf import settings
from cryptography.fernet import Fernet


def derive_encryption_key():
    """
    Tạo key mã hóa từ Django SECRET_KEY
    
    Returns:
        bytes: URL-safe base64 encoded key
    """
    digest = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
    return base64.urlsafe_b64encode(digest)


def get_fernet():
    """
    Lấy Fernet instance để mã hóa/giải mã
    
    Returns:
        Fernet: Fernet cipher instance
    """
    return Fernet(derive_encryption_key())


def find_pyhanko_executable(preferred=None):
    """
    Tìm pyhanko executable trong hệ thống
    
    Args:
        preferred: Đường dẫn ưu tiên đến pyhanko
        
    Returns:
        str: Đường dẫn đến pyhanko executable hoặc None nếu không tìm thấy
    """
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
