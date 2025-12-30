#!/usr/bin/env python3
"""Issue a user certificate and store encrypted PKCS#12 for local development.

Usage: python scripts/issue_cert.py <username> [passphrase]

This mirrors the logic in `signing/auth.py` but can be run without the Django server.
"""
import sys
import os
import subprocess
import hashlib
import base64
from pathlib import Path
from cryptography.fernet import Fernet
import re
import json
import traceback


def read_secret_key(settings_path: Path) -> str:
    txt = settings_path.read_text(encoding='utf-8')
    m = re.search(r"SECRET_KEY\s*=\s*['\"](.+?)['\"]", txt)
    if not m:
        raise RuntimeError('SECRET_KEY not found in settings.py')
    return m.group(1)


def derive_key(secret_key: str) -> bytes:
    digest = hashlib.sha256(secret_key.encode()).digest()
    return base64.urlsafe_b64encode(digest)


def main():
    if len(sys.argv) < 2:
        print('Usage: issue_cert.py <username> [passphrase]')
        sys.exit(1)
    username = sys.argv[1]
    passphrase = sys.argv[2] if len(sys.argv) > 2 else 'changeit'

    project_root = Path(__file__).resolve().parents[1]
    settings_path = project_root / 'backend' / 'settings.py'
    secret_key = read_secret_key(settings_path)
    key = derive_key(secret_key)
    fernet = Fernet(key)

    user_dir = project_root / 'users' / username
    user_dir.mkdir(parents=True, exist_ok=True)

    # locate intermediate CA cert/key in common repo locations
    def find_intermediate_paths(root: Path):
        # check old path
        candidates = [root / 'CA' / 'intermediate-ca', root / 'certs' / 'intermediate-ca', root / 'certs']
        for c in candidates:
            cert1 = c / 'certs' / 'intermediate.crt'
            cert2 = c / 'intermediate.crt'
            cert3 = c / 'intermediateCA.crt'
            if cert1.exists():
                # search for key
                key = c / 'private' / 'intermediate.key'
                return cert1, key
            if cert2.exists():
                key = c / 'private' / 'intermediate.key'
                return cert2, key
            if cert3.exists():
                key = c / 'private' / 'intermediate.key'
                return cert3, key
        # fallback: try to find any matching files under root
        cert_found = None
        key_found = None
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
        subj = f"/CN={username}/emailAddress={username}@dut.local"
        messages.append('Creating CSR')
        subprocess.run(['openssl', 'req', '-new', '-key', str(key_path), '-subj', subj, '-out', str(csr_path)], check=True)
        messages.append('Signing with intermediate CA')
        # if user provided an extensions file, use it so keyUsage/extendedKeyUsage are set
        extfile = user_dir / 'v3_ext.cnf'
        if extfile.exists():
            subprocess.run([
                'openssl', 'x509', '-req', '-in', str(csr_path), '-CA', str(interm_cert), '-CAkey', str(interm_key),
                '-CAcreateserial', '-out', str(crt_path), '-days', '365', '-sha256', '-extfile', str(extfile), '-extensions', 'v3_req'
            ], check=True)
        else:
            subprocess.run(['openssl', 'x509', '-req', '-in', str(csr_path), '-CA', str(interm_cert), '-CAkey', str(interm_key), '-CAcreateserial', '-out', str(crt_path), '-days', '365', '-sha256'], check=True)
        messages.append('Exporting PKCS#12')
        subprocess.run(['openssl', 'pkcs12', '-export', '-inkey', str(key_path), '-in', str(crt_path), '-certfile', str(interm_cert), '-out', str(p12_path), '-passout', f'pass:{passphrase}'], check=True)

        messages.append('Encrypting PKCS#12 and passphrase')
        data = p12_path.read_bytes()
        enc = fernet.encrypt(data)
        enc_path = user_dir / 'user.p12.enc'
        pass_enc_path = user_dir / 'p12.pass.enc'
        enc_path.write_bytes(enc)
        pass_enc_path.write_bytes(fernet.encrypt(passphrase.encode('utf-8')))

        result = {
            'ok': True,
            'username': username,
            'p12_path': str(p12_path),
            'p12_enc_path': str(enc_path),
            'p12_pass_enc_path': str(pass_enc_path),
            'messages': messages,
        }
        print(json.dumps(result))
        return 0
    except Exception as e:
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
