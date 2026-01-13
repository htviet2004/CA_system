
import os
import sys
import subprocess
import tempfile
import json
import time
from django.conf import settings
from usercerts.models import UserCert
from .utils import get_fernet


class CertificateService:
    
    @staticmethod
    def find_user_certificate(user, username):
        enc_p12 = None
        enc_pass = None
        
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
                
            if os.path.exists(p) and os.path.exists(pp):
                enc_p12 = p
                enc_pass = pp
        
        if not enc_p12 or not enc_pass:
            user_dir = os.path.join(settings.BASE_DIR, 'users', username)
            fs_p12 = os.path.join(user_dir, 'user.p12.enc')
            fs_pass = os.path.join(user_dir, 'p12.pass.enc')
            
            if os.path.exists(fs_p12) and os.path.exists(fs_pass):
                enc_p12 = fs_p12
                enc_pass = fs_pass
        
        return enc_p12, enc_pass
    
    @staticmethod
    def decrypt_certificate(enc_p12_path, enc_pass_path):
        fernet = get_fernet()
        
        with open(enc_p12_path, 'rb') as fh:
            p12_data = fernet.decrypt(fh.read())
        
        with open(enc_pass_path, 'rb') as fh:
            pass_data = fernet.decrypt(fh.read()).decode('utf-8')
        
        return p12_data, pass_data
    
    @staticmethod
    def auto_issue_certificate(username, password=None):
        script = os.path.join(settings.BASE_DIR, 'scripts', 'issue_cert.py')
        user_dir = os.path.join(settings.BASE_DIR, 'users', username)
        
        plain_pass_file = os.path.join(user_dir, 'p12.pass')
        if os.path.exists(plain_pass_file):
            passphrase = open(plain_pass_file, 'r', encoding='utf-8').read().strip()
        else:
            passphrase = password or 'changeit'
        
        proc = subprocess.run(
            [sys.executable, script, username, passphrase], 
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
            
            if ep and pp and os.path.exists(ep) and os.path.exists(pp):
                return ep, pp
        
        raise RuntimeError(f'Auto-issue certificate failed: {proc.stderr or proc.stdout}')
    
    @staticmethod
    def create_temp_files(p12_data, passphrase):
        
        p12_tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.p12')
        p12_tmp.write(p12_data)
        p12_tmp.flush()
        p12_tmp.close()
        
        pass_tmp = tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.txt')
        pass_tmp.write(passphrase)
        pass_tmp.flush()
        pass_tmp.close()
        
        return p12_tmp.name, pass_tmp.name
    
    @staticmethod
    def cleanup_temp_files(*paths):
        
        for path in paths:
            try:
                if path and os.path.exists(path):
                    os.unlink(path)
            except Exception:
                pass
