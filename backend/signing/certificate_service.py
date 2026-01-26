"""
Certificate service for finding, decrypting, and managing user certificates.

SECURITY: All file operations validate paths and use secure practices.
"""
import os
import sys
import subprocess
import tempfile
import json
import time
import secrets
import logging

from django.conf import settings
from usercerts.models import UserCert
from .utils import get_fernet, generate_secure_passphrase
from .validators import validate_username

logger = logging.getLogger(__name__)


class CertificateService:
    """Service class for certificate operations."""
    
    @staticmethod
    def find_user_certificate(user, username):
        """
        Find a user's encrypted certificate files.
        
        SECURITY: Validates username to prevent path traversal.
        Returns (enc_p12_path, enc_pass_path) or (None, None) if not found.
        """
        # SECURITY: Validate username before using in path
        try:
            username = validate_username(username)
        except ValueError as e:
            logger.warning(f"Invalid username in find_user_certificate: {e}")
            return None, None
        
        enc_p12 = None
        enc_pass = None
        
        # Try database first
        uc = UserCert.objects.filter(
            user=user, 
            active=True
        ).order_by('-created_at').first()
        
        if uc:
            p = uc.p12_enc_path or ''
            pp = uc.p12_pass_enc_path or ''
            
            if p and not os.path.isabs(p):
                p = os.path.join(settings.BASE_DIR, p)
            if pp and not os.path.isabs(pp):
                pp = os.path.join(settings.BASE_DIR, pp)
            
            # SECURITY: Verify paths are within expected directory
            base_dir = os.path.realpath(settings.BASE_DIR)
            if (os.path.exists(p) and os.path.exists(pp) and
                os.path.realpath(p).startswith(base_dir) and
                os.path.realpath(pp).startswith(base_dir)):
                enc_p12 = p
                enc_pass = pp
        
        # Fallback to filesystem
        if not enc_p12 or not enc_pass:
            user_dir = os.path.join(settings.BASE_DIR, 'users', username)
            fs_p12 = os.path.join(user_dir, 'user.p12.enc')
            fs_pass = os.path.join(user_dir, 'p12.pass.enc')
            
            # SECURITY: Verify paths are within expected directory
            base_dir = os.path.realpath(settings.BASE_DIR)
            if (os.path.exists(fs_p12) and os.path.exists(fs_pass) and
                os.path.realpath(fs_p12).startswith(base_dir) and
                os.path.realpath(fs_pass).startswith(base_dir)):
                enc_p12 = fs_p12
                enc_pass = fs_pass
        
        return enc_p12, enc_pass
    
    @staticmethod
    def decrypt_certificate(enc_p12_path, enc_pass_path):
        """
        Decrypt encrypted PKCS#12 and passphrase files.
        
        Returns (p12_data_bytes, passphrase_string).
        """
        fernet = get_fernet()
        
        with open(enc_p12_path, 'rb') as fh:
            p12_data = fernet.decrypt(fh.read())
        
        with open(enc_pass_path, 'rb') as fh:
            pass_data = fernet.decrypt(fh.read()).decode('utf-8')
        
        return p12_data, pass_data
    
    @staticmethod
    def auto_issue_certificate(username, password=None):
        """
        Automatically issue a new certificate for a user.
        
        SECURITY: 
        - Validates username to prevent path traversal
        - Uses secure passphrase generation
        - Does NOT pass passphrase via command line (issue_cert.py generates its own)
        
        Returns (enc_p12_path, enc_pass_path).
        """
        # SECURITY: Validate username
        username = validate_username(username)
        
        script = os.path.join(settings.BASE_DIR, 'scripts', 'issue_cert.py')
        
        # SECURITY: Only pass username, let the script generate a secure passphrase
        # The script will create and encrypt its own passphrase
        proc = subprocess.run(
            [sys.executable, script, username], 
            capture_output=True, 
            text=True
        )
        
        time.sleep(0.2)
        
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
            
            # SECURITY: Verify paths are within expected directory
            base_dir = os.path.realpath(settings.BASE_DIR)
            if (ep and pp and os.path.exists(ep) and os.path.exists(pp) and
                os.path.realpath(ep).startswith(base_dir) and
                os.path.realpath(pp).startswith(base_dir)):
                logger.info(f"Certificate auto-issued for user: {username}")
                return ep, pp
        
        logger.error(f"Auto-issue certificate failed for {username}: {proc.stderr or proc.stdout}")
        raise RuntimeError(f'Auto-issue certificate failed: {proc.stderr or proc.stdout}')
    
    @staticmethod
    def create_temp_files(p12_data, passphrase):
        """
        Create temporary files for PKCS#12 data and passphrase.
        
        SECURITY: Sets restrictive permissions (0600) on temp files.
        Caller MUST use cleanup_temp_files() to securely delete.
        
        Returns (p12_tmp_path, pass_tmp_path).
        """
        # Create p12 temp file with secure permissions
        p12_fd, p12_path = tempfile.mkstemp(suffix='.p12')
        try:
            os.chmod(p12_path, 0o600)
            os.write(p12_fd, p12_data)
        finally:
            os.close(p12_fd)
        
        # Create passphrase temp file with secure permissions
        pass_fd, pass_path = tempfile.mkstemp(suffix='.txt')
        try:
            os.chmod(pass_path, 0o600)
            os.write(pass_fd, passphrase.encode('utf-8'))
        finally:
            os.close(pass_fd)
        
        return p12_path, pass_path
    
    @staticmethod
    def cleanup_temp_files(*paths):
        """
        Securely clean up temporary files.
        
        SECURITY: Overwrites files with random data before deletion
        to prevent recovery.
        """
        for path in paths:
            try:
                if path and os.path.exists(path):
                    # SECURITY: Overwrite with random data before deletion
                    file_size = os.path.getsize(path)
                    with open(path, 'wb') as f:
                        f.write(secrets.token_bytes(file_size))
                        f.flush()
                        os.fsync(f.fileno())
                    os.unlink(path)
            except Exception as e:
                logger.warning(f"Failed to securely delete temp file {path}: {e}")
                try:
                    os.unlink(path)
                except Exception:
                    pass
