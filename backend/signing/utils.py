"""
Cryptographic utilities for the CA system.

SECURITY NOTES:
- Key derivation uses PBKDF2 with high iteration count (not raw SHA256)
- Fernet provides AES-128-CBC encryption with HMAC authentication
- All sensitive material should be cleared from memory after use
"""

import hashlib
import base64
import os
import shutil
import secrets
import logging
from functools import lru_cache
from typing import Optional

from django.conf import settings
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .constants import (
    PBKDF2_ITERATIONS,
    PBKDF2_KEY_LENGTH,
    PBKDF2_SALT_ENV_VAR,
    PASSWORD_MIN_LENGTH,
)

logger = logging.getLogger(__name__)


def _get_pbkdf2_salt() -> bytes:
    """
    Get the salt for PBKDF2 key derivation.
    
    SECURITY: Salt should be unique per deployment. If not set via environment,
    we derive a deterministic salt from SECRET_KEY (less ideal but maintains
    backward compatibility during migration).
    """
    env_salt = os.environ.get(PBKDF2_SALT_ENV_VAR)
    if env_salt:
        # SECURITY: Environment-provided salt is preferred
        return env_salt.encode('utf-8')
    else:
        # SECURITY: Fallback - derive salt from SECRET_KEY
        # This is less ideal but ensures existing encrypted data can still be read
        # Log a warning to encourage setting explicit salt
        logger.warning(
            "FERNET_SALT not set in environment. Using derived salt. "
            "Set FERNET_SALT for better security."
        )
        # Use first 32 bytes of SHA256(SECRET_KEY) as salt
        return hashlib.sha256(
            f"salt:{settings.SECRET_KEY}".encode('utf-8')
        ).digest()


def derive_encryption_key() -> bytes:
    """
    Derive a Fernet-compatible encryption key using PBKDF2.
    
    SECURITY: Uses PBKDF2 with high iteration count instead of raw SHA256.
    This makes brute-force attacks significantly more expensive.
    
    Returns:
        bytes: URL-safe base64 encoded 32-byte key suitable for Fernet
    """
    salt = _get_pbkdf2_salt()
    
    # SECURITY: PBKDF2 with high iteration count for key stretching
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=PBKDF2_KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    
    key_material = kdf.derive(settings.SECRET_KEY.encode('utf-8'))
    return base64.urlsafe_b64encode(key_material)


@lru_cache(maxsize=1)
def get_fernet() -> Fernet:
    """
    Get a cached Fernet instance for encryption/decryption.
    
    SECURITY: Caching prevents repeated key derivation, which is intentionally slow.
    The cache is invalidated on server restart.
    
    Returns:
        Fernet: Configured Fernet instance
    """
    return Fernet(derive_encryption_key())


def generate_secure_passphrase(length: int = PASSWORD_MIN_LENGTH) -> str:
    """
    Generate a cryptographically secure passphrase.
    
    SECURITY: Uses secrets module (CSPRNG) instead of random.
    Output is URL-safe base64 for compatibility with shell and file systems.
    
    Args:
        length: Minimum number of characters (actual may be slightly more)
    
    Returns:
        str: Secure random passphrase
    """
    # SECURITY: secrets.token_urlsafe uses os.urandom (CSPRNG)
    # Each character provides ~6 bits of entropy
    return secrets.token_urlsafe(length)


def clear_sensitive_string(s: str) -> None:
    """
    Attempt to clear a sensitive string from memory.
    
    SECURITY: Python strings are immutable, so true secure erasure is not possible.
    This is a best-effort attempt. For critical secrets, consider using:
    - ctypes to overwrite memory
    - mlock to prevent swapping
    - Dedicated secure memory libraries
    
    Args:
        s: String to clear (note: original cannot be modified)
    """
    # SECURITY: Best-effort attempt - Python doesn't guarantee string memory clearing
    # In production, consider using SecureString or similar constructs
    pass  # Document limitation - Python strings cannot be securely erased


def validate_environment_secrets() -> None:
    """
    Validate that required secrets are configured in environment.
    
    SECURITY: Called at startup to ensure system cannot run with insecure defaults.
    Raises ImproperlyConfigured if required secrets are missing.
    """
    from django.core.exceptions import ImproperlyConfigured
    from .constants import REQUIRED_ENV_VARS
    
    missing = []
    for var in REQUIRED_ENV_VARS:
        value = os.environ.get(var)
        if not value:
            missing.append(var)
        elif var == 'SECRET_KEY':
            # SECURITY: Reject known insecure default keys
            if 'django-insecure' in value.lower() or value == 'your-super-secret-key-here':
                raise ImproperlyConfigured(
                    f"SECRET_KEY contains insecure default value. "
                    f"Generate a secure key with: python -c \"import secrets; print(secrets.token_urlsafe(50))\""
                )
    
    if missing:
        raise ImproperlyConfigured(
            f"Required environment variables not set: {', '.join(missing)}. "
            f"Copy .env.example to .env and configure all required values."
        )


def find_pyhanko_executable(preferred: Optional[str] = None) -> Optional[str]:
    """
    Find the pyhanko CLI executable.
    
    Args:
        preferred: Preferred path or command name
    
    Returns:
        str: Path to pyhanko executable, or None if not found
    """
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
        candidates.append(os.path.join(base, venv_name, 'bin', 'pyhanko'))

    candidates.append(os.path.join(base, '..', 'env', 'Scripts', 'pyhanko.exe'))
    candidates.append(os.path.join(base, '..', 'env', 'Scripts', 'pyhanko'))
    candidates.append(os.path.join(base, '..', 'env', 'bin', 'pyhanko'))

    for c in candidates:
        if c and os.path.exists(c):
            return c

    path = shutil.which('pyhanko')
    if path:
        return path
    return None
