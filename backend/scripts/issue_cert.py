#!/usr/bin/env python3
"""Issue a user certificate and store encrypted PKCS#12 for local development.

Usage: python scripts/issue_cert.py <username> [passphrase]

This mirrors the logic in `signing/auth.py` but can be run without the Django server.

SECURITY NOTES:
- Uses PBKDF2 for key derivation (not raw SHA256)
- Passes passwords via stdin to OpenSSL (not command line)
- Securely deletes private key files after PKCS#12 export
- Validates username to prevent path traversal
"""
import sys
import os
import subprocess
import hashlib
import base64
import secrets
import re
import json
import traceback
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# SECURITY: Import constants from signing module if available, else define locally
try:
    from signing.constants import PBKDF2_ITERATIONS, USERNAME_PATTERN, PASSWORD_MIN_LENGTH
except ImportError:
    PBKDF2_ITERATIONS = 480_000
    USERNAME_PATTERN = re.compile(r'^[a-zA-Z][a-zA-Z0-9_-]{2,31}$')
    PASSWORD_MIN_LENGTH = 24


def validate_username(username: str) -> str:
    """
    Validate username format.
    
    SECURITY: Prevents path traversal and injection attacks.
    """
    if not username or not isinstance(username, str):
        raise ValueError("Username is required")
    
    username = username.strip()
    
    if not USERNAME_PATTERN.match(username):
        raise ValueError(
            "Invalid username. Must be 3-32 characters, start with a letter, "
            "and contain only letters, numbers, underscores, and hyphens."
        )
    
    return username


def get_fernet_salt() -> bytes:
    """Get salt for key derivation from environment or generate."""
    salt_str = os.environ.get('FERNET_SALT')
    if salt_str:
        return salt_str.encode('utf-8')
    # Fallback for development - use a fixed salt (NOT recommended for production)
    return b'ca_system_development_salt_v1'


def read_secret_key(settings_path: Path) -> str:
    """Read SECRET_KEY from settings or environment."""
    # SECURITY: Prefer environment variable
    env_key = os.environ.get('SECRET_KEY')
    if env_key:
        return env_key
    
    # Fallback to reading from settings file
    txt = settings_path.read_text(encoding='utf-8')
    m = re.search(r"SECRET_KEY\s*=\s*['\"](.+?)['\"]", txt)
    if not m:
        raise RuntimeError('SECRET_KEY not found in settings.py or environment')
    return m.group(1)


def derive_key(secret_key: str) -> bytes:
    """
    Derive Fernet key using PBKDF2.
    
    SECURITY: Uses PBKDF2 with 480,000 iterations instead of raw SHA256.
    This matches the implementation in signing/utils.py.
    """
    salt = get_fernet_salt()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(secret_key.encode('utf-8')))


def generate_secure_passphrase(length: int = PASSWORD_MIN_LENGTH) -> str:
    """
    Generate a cryptographically secure passphrase.
    
    SECURITY: Uses secrets module for secure random generation.
    """
    return secrets.token_urlsafe(length)


def secure_delete_file(filepath: Path) -> None:
    """
    Securely delete a file by overwriting with random data before removal.
    
    SECURITY: Prevents recovery of sensitive key material.
    """
    if not filepath.exists():
        return
    
    try:
        file_size = filepath.stat().st_size
        # Overwrite with random data 3 times
        for _ in range(3):
            with open(filepath, 'wb') as f:
                f.write(secrets.token_bytes(file_size))
                f.flush()
                os.fsync(f.fileno())
        # Final overwrite with zeros
        with open(filepath, 'wb') as f:
            f.write(b'\x00' * file_size)
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        pass  # Best effort - still try to delete
    finally:
        try:
            filepath.unlink()
        except Exception:
            pass


def main():
    if len(sys.argv) < 2:
        print('Usage: issue_cert.py <username> [passphrase]')
        sys.exit(1)
    
    # SECURITY: Validate username
    try:
        username = validate_username(sys.argv[1])
    except ValueError as e:
        print(json.dumps({'ok': False, 'error': str(e)}))
        sys.exit(1)
    
    # SECURITY: Generate secure passphrase if not provided
    passphrase = sys.argv[2] if len(sys.argv) > 2 else generate_secure_passphrase()

    project_root = Path(__file__).resolve().parents[1]
    settings_path = project_root / 'backend' / 'settings.py'
    secret_key = read_secret_key(settings_path)
    key = derive_key(secret_key)
    fernet = Fernet(key)

    user_dir = project_root / 'users' / username
    user_dir.mkdir(parents=True, exist_ok=True)

    # locate intermediate CA cert/key in common repo locations
    def find_intermediate_paths(root: Path):
        # Prioritize intermediateCA.crt over intermediate.crt
        candidates = [root / 'CA' / 'intermediate-ca', root / 'certs' / 'intermediate-ca', root / 'certs']
        for c in candidates:
            # Try intermediateCA.crt first (proper intermediate CA)
            cert1 = c / 'certs' / 'intermediateCA.crt'
            if cert1.exists():
                key = c / 'private' / 'intermediate.key'
                if key.exists():
                    return cert1, key
            
            # Fallback to intermediate.crt
            cert2 = c / 'certs' / 'intermediate.crt'
            if cert2.exists():
                key = c / 'private' / 'intermediate.key'
                if key.exists():
                    return cert2, key
            
            cert3 = c / 'intermediate.crt'
            if cert3.exists():
                key = c / 'private' / 'intermediate.key'
                return cert3, key
                
            cert4 = c / 'intermediateCA.crt'
            if cert4.exists():
                key = c / 'private' / 'intermediate.key'
                return cert4, key
        
        # fallback: try to find any matching files under root
        cert_found = None
        key_found = None
        # Try intermediateCA first
        for p in root.rglob('intermediateCA.crt'):
            cert_found = p
            break
        if not cert_found:
            for p in root.rglob('intermediate*.crt'):
                cert_found = p
                break
        for p in root.rglob('intermediate*.key'):
            key_found = p
            break
        return cert_found, key_found

    interm_cert, interm_key = find_intermediate_paths(project_root)
    if not interm_cert or not interm_key or not interm_key.exists():
        raise RuntimeError(f'Intermediate CA cert/key not found. cert={interm_cert} key={interm_key}')

    key_path = user_dir / f'{username}.key'
    csr_path = user_dir / f'{username}.csr'
    crt_path = user_dir / f'{username}.crt'
    p12_path = user_dir / f'{username}.p12'

    messages = []
    try:
        messages.append('Generating key')
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', str(key_path)], check=True)
        
        # Thông tin certificate chuẩn cho DUT
        # Tùy chỉnh OU dựa vào role: Student, Faculty, Staff, Admin
        subj = (
            f"/C=VN"
            f"/ST=Da Nang"
            f"/L=Da Nang"
            f"/O=Da Nang University of Science and Technology"
            f"/OU=Student"  # Hoặc: Faculty, Staff, Admin
            f"/CN={username}"
            f"/emailAddress={username}@dut.udn.vn"
        )
        
        messages.append('Creating CSR')
        subprocess.run(['openssl', 'req', '-new', '-key', str(key_path), '-subj', subj, '-out', str(csr_path)], check=True)
        messages.append('Signing with intermediate CA')
        
        # Create v3 extension file if it doesn't exist
        extfile = user_dir / 'v3_ext.cnf'
        if not extfile.exists():
            messages.append('Creating v3 extension file')
            extfile.write_text("""[ v3_req ]
keyUsage = critical, digitalSignature, nonRepudiation
extendedKeyUsage = emailProtection, clientAuth
""", encoding='utf-8')
        
        # Always use extensions file for proper keyUsage
        subprocess.run([
            'openssl', 'x509', '-req', '-in', str(csr_path), '-CA', str(interm_cert), '-CAkey', str(interm_key),
            '-CAcreateserial', '-out', str(crt_path), '-days', '365', '-sha256', '-extfile', str(extfile), '-extensions', 'v3_req'
        ], check=True)
        
        messages.append('Exporting PKCS#12')
        # SECURITY: Pass password via stdin instead of command line
        p12_export = subprocess.run(
            [
                'openssl', 'pkcs12', '-export', 
                '-inkey', str(key_path), 
                '-in', str(crt_path), 
                '-certfile', str(interm_cert), 
                '-out', str(p12_path), 
                '-passout', 'stdin'
            ],
            input=passphrase.encode('utf-8'),
            check=True
        )

        messages.append('Encrypting PKCS#12 and passphrase')
        data = p12_path.read_bytes()
        enc = fernet.encrypt(data)
        enc_path = user_dir / 'user.p12.enc'
        pass_enc_path = user_dir / 'p12.pass.enc'
        enc_path.write_bytes(enc)
        pass_enc_path.write_bytes(fernet.encrypt(passphrase.encode('utf-8')))

        # SECURITY: Clean up sensitive intermediate files
        messages.append('Cleaning up sensitive files')
        secure_delete_file(key_path)
        secure_delete_file(csr_path)
        secure_delete_file(crt_path)
        secure_delete_file(p12_path)

        result = {
            'ok': True,
            'username': username,
            'p12_enc_path': str(enc_path),
            'p12_pass_enc_path': str(pass_enc_path),
            'messages': messages,
            'note': 'Private key and unencrypted files have been securely deleted'
        }
        print(json.dumps(result))
        return 0
    except Exception as e:
        # SECURITY: Clean up sensitive files even on error
        for path in [key_path, csr_path, crt_path, p12_path]:
            secure_delete_file(path)
        
        tb = traceback.format_exc()
        result = {
            'ok': False,
            'username': username,
            'error': str(e),
            'traceback': tb,
            'messages': messages,
        }
        print(json.dumps(result))
        return 2


if __name__ == '__main__':
    sys.exit(main())
