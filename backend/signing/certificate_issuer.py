"""
Centralized Certificate Issuance Service.

SECURITY: This module consolidates all certificate generation logic to ensure
consistent security practices across the application.

Key security features:
- PBKDF2-based key derivation for Fernet encryption
- Secure passphrase generation using secrets module
- Password passing via stdin to OpenSSL (not command line)
- Secure deletion of private keys after P12 export
- Username validation to prevent path traversal
"""
import os
import subprocess
import secrets
import logging
from pathlib import Path

from django.conf import settings

from .utils import get_fernet, generate_secure_passphrase
from .validators import validate_username, validate_common_name

logger = logging.getLogger(__name__)


class CertificateIssuer:
    """
    Service for issuing X.509 certificates.
    
    Handles the complete certificate lifecycle:
    1. Generate RSA key pair
    2. Create CSR with validated subject
    3. Sign with intermediate CA
    4. Export to PKCS#12
    5. Encrypt P12 and passphrase with Fernet
    6. Securely delete plaintext private key material
    """
    
    def __init__(self):
        self.project_root = Path(settings.BASE_DIR)
        self.interm_cert, self.interm_key = self._find_intermediate_ca()
    
    def _find_intermediate_ca(self):
        """
        Locate intermediate CA certificate and key.
        
        Returns (cert_path, key_path) or raises RuntimeError if not found.
        """
        root = self.project_root
        candidates = [
            root / 'CA' / 'intermediate-ca',
            root / 'certs' / 'intermediate-ca',
            root / 'certs'
        ]
        
        for c in candidates:
            # Try various naming conventions
            for cert_name in ['intermediateCA.crt', 'intermediate.crt']:
                cert_path = c / 'certs' / cert_name
                if not cert_path.exists():
                    cert_path = c / cert_name
                
                key_path = c / 'private' / 'intermediate.key'
                
                if cert_path.exists() and key_path.exists():
                    logger.debug(f"Found intermediate CA: cert={cert_path}, key={key_path}")
                    return cert_path, key_path
        
        # Fallback: glob search
        cert_found = None
        key_found = None
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
        
        if cert_found and key_found:
            return cert_found, key_found
        
        raise RuntimeError(f'Intermediate CA not found. cert={cert_found}, key={key_found}')
    
    def issue_certificate(self, username, common_name=None, email=None, 
                          organization="Da Nang University of Science and Technology",
                          organizational_unit="User", country="VN", 
                          state="Da Nang", locality="Da Nang"):
        """
        Issue a new certificate for a user.
        
        Args:
            username: The username (validated)
            common_name: CN for the certificate (defaults to username)
            email: Email address for certificate
            organization: O field
            organizational_unit: OU field
            country: C field
            state: ST field
            locality: L field
        
        Returns:
            dict with keys:
                - ok: bool
                - p12_enc_path: str (relative to BASE_DIR)
                - p12_pass_enc_path: str (relative to BASE_DIR)
                - error: str (if ok=False)
        
        SECURITY:
        - Validates username to prevent path traversal
        - Generates secure passphrase (not user-provided)
        - Passes passphrase via stdin to openssl
        - Securely deletes private key material
        """
        # SECURITY: Validate inputs
        try:
            username = validate_username(username)
            cn = validate_common_name(common_name or username)
        except ValueError as e:
            return {'ok': False, 'error': str(e)}
        
        # Set default email if not provided
        if not email:
            email = f"{username}@dut.udn.vn"
        
        # SECURITY: Generate cryptographically secure passphrase
        passphrase = generate_secure_passphrase()
        
        # Setup paths
        user_dir = self.project_root / 'users' / username
        user_dir.mkdir(parents=True, exist_ok=True)
        
        key_path = user_dir / f'{username}.key'
        csr_path = user_dir / f'{username}.csr'
        crt_path = user_dir / f'{username}.crt'
        p12_path = user_dir / f'{username}.p12'
        p12_enc_path = user_dir / 'user.p12.enc'
        pass_enc_path = user_dir / 'p12.pass.enc'
        
        try:
            # Step 1: Generate RSA key pair
            logger.debug(f"Generating RSA key for {username}")
            subprocess.run(
                ['openssl', 'genpkey', '-algorithm', 'RSA', 
                 '-pkeyopt', 'rsa_keygen_bits:2048', '-out', str(key_path)],
                check=True,
                capture_output=True
            )
            
            # Step 2: Create CSR
            subj = (
                f"/C={country}"
                f"/ST={state}"
                f"/L={locality}"
                f"/O={organization}"
                f"/OU={organizational_unit}"
                f"/CN={cn}"
                f"/emailAddress={email}"
            )
            
            logger.debug(f"Creating CSR for {username}")
            subprocess.run(
                ['openssl', 'req', '-new', '-key', str(key_path), 
                 '-subj', subj, '-out', str(csr_path)],
                check=True,
                capture_output=True
            )
            
            # Step 3: Sign with intermediate CA
            logger.debug(f"Signing certificate for {username}")
            
            # Create or use existing v3 extensions file
            extfile = user_dir / 'v3_ext.cnf'
            if not extfile.exists():
                extfile.write_text("""[ v3_req ]
keyUsage = critical, digitalSignature, nonRepudiation
extendedKeyUsage = emailProtection, clientAuth
""", encoding='utf-8')
            
            subprocess.run(
                ['openssl', 'x509', '-req', 
                 '-in', str(csr_path), 
                 '-CA', str(self.interm_cert), 
                 '-CAkey', str(self.interm_key),
                 '-CAcreateserial', 
                 '-out', str(crt_path), 
                 '-days', '365', 
                 '-sha256',
                 '-extfile', str(extfile),
                 '-extensions', 'v3_req'],
                check=True,
                capture_output=True
            )
            
            # Step 4: Export to PKCS#12 (passphrase via stdin)
            logger.debug(f"Exporting PKCS#12 for {username}")
            result = subprocess.run(
                ['openssl', 'pkcs12', '-export',
                 '-inkey', str(key_path),
                 '-in', str(crt_path),
                 '-certfile', str(self.interm_cert),
                 '-out', str(p12_path),
                 '-passout', 'stdin'],
                input=passphrase.encode('utf-8'),
                check=True,
                capture_output=True
            )
            
            # Step 5: Encrypt P12 and passphrase with Fernet
            logger.debug(f"Encrypting certificate for {username}")
            fernet = get_fernet()
            
            p12_data = p12_path.read_bytes()
            p12_enc_path.write_bytes(fernet.encrypt(p12_data))
            pass_enc_path.write_bytes(fernet.encrypt(passphrase.encode('utf-8')))
            
            # Step 6: Securely delete plaintext files
            logger.debug(f"Cleaning up plaintext files for {username}")
            self._secure_delete(key_path)
            self._secure_delete(csr_path)
            self._secure_delete(crt_path)
            self._secure_delete(p12_path)
            
            logger.info(f"Certificate issued successfully for {username}")
            
            return {
                'ok': True,
                'p12_enc_path': str(p12_enc_path.relative_to(self.project_root)),
                'p12_pass_enc_path': str(pass_enc_path.relative_to(self.project_root)),
            }
            
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.decode('utf-8', errors='replace') if e.stderr else str(e)
            logger.error(f"OpenSSL error for {username}: {error_msg}")
            
            # Clean up any partial files
            for path in [key_path, csr_path, crt_path, p12_path]:
                self._secure_delete(path)
            
            return {'ok': False, 'error': f'Certificate generation failed: {error_msg}'}
            
        except Exception as e:
            logger.error(f"Certificate issuance failed for {username}: {e}")
            
            # Clean up any partial files
            for path in [key_path, csr_path, crt_path, p12_path]:
                self._secure_delete(path)
            
            return {'ok': False, 'error': str(e)}
    
    def _secure_delete(self, filepath):
        """
        Securely delete a file by overwriting with random data before removal.
        
        SECURITY: Prevents recovery of sensitive key material.
        """
        filepath = Path(filepath)
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
        except Exception as e:
            logger.warning(f"Secure overwrite failed for {filepath}: {e}")
        finally:
            try:
                filepath.unlink()
            except Exception as e:
                logger.warning(f"Failed to delete {filepath}: {e}")


# Singleton instance for convenience
_issuer = None

def get_certificate_issuer():
    """Get the singleton CertificateIssuer instance."""
    global _issuer
    if _issuer is None:
        _issuer = CertificateIssuer()
    return _issuer


def issue_user_certificate(username, **kwargs):
    """
    Convenience function to issue a certificate.
    
    See CertificateIssuer.issue_certificate() for full documentation.
    """
    return get_certificate_issuer().issue_certificate(username, **kwargs)
