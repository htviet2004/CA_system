"""
PDF Signing service using pyHanko.

SECURITY: Manages temporary files securely and validates inputs.
"""
import os
import tempfile
import time
import secrets
import logging
from datetime import datetime
from pyhanko.sign import signers, fields as ph_fields, timestamps as ph_timestamps
from pyhanko.sign.fields import SigFieldSpec
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from django.conf import settings

from .validators import validate_username

logger = logging.getLogger(__name__)


class PDFSigner:
    """Context manager for signing PDFs with PKCS#12 certificates."""
    
    def __init__(self, p12_data, passphrase, username):
        """
        Initialize PDF signer.
        
        SECURITY: Validates username to prevent injection attacks.
        """
        # SECURITY: Validate username
        self.username = validate_username(username)
        self.p12_data = p12_data
        self.passphrase = passphrase
        self.p12_tmp = None
        self.pass_tmp = None
        self._p12_path = None
        self._pass_path = None
    
    def __enter__(self):
        """Create secure temporary files for PKCS#12 and passphrase."""
        # SECURITY: Create temp files with restrictive permissions
        p12_fd, self._p12_path = tempfile.mkstemp(suffix='.p12')
        try:
            os.chmod(self._p12_path, 0o600)
            os.write(p12_fd, self.p12_data)
        finally:
            os.close(p12_fd)
        
        pass_fd, self._pass_path = tempfile.mkstemp(suffix='.txt')
        try:
            os.chmod(self._pass_path, 0o600)
            os.write(pass_fd, self.passphrase.encode('utf-8'))
        finally:
            os.close(pass_fd)
        
        # Create mock file objects for backward compatibility
        class TempFile:
            def __init__(self, path):
                self.name = path
        
        self.p12_tmp = TempFile(self._p12_path)
        self.pass_tmp = TempFile(self._pass_path)
        
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Securely delete temporary files."""
        self._secure_cleanup(self._p12_path)
        self._secure_cleanup(self._pass_path)
    
    def _secure_cleanup(self, path):
        """
        Securely delete a file by overwriting before removal.
        
        SECURITY: Prevents recovery of sensitive key material.
        """
        if not path or not os.path.exists(path):
            return
        
        try:
            file_size = os.path.getsize(path)
            # Overwrite with random data
            with open(path, 'wb') as f:
                f.write(secrets.token_bytes(file_size))
                f.flush()
                os.fsync(f.fileno())
            os.unlink(path)
        except Exception as e:
            logger.warning(f"Failed to securely delete {path}: {e}")
            try:
                os.unlink(path)
            except Exception:
                pass
    
    def parse_position(self, position_str):
        
        if not position_str:
            raise ValueError('Vui lòng chọn vị trí chữ ký trên PDF')
        
        try:
            parts = position_str.split('/')
            if len(parts) != 2:
                raise ValueError('Format position không đúng')
            
            page = int(parts[0])
            coords = list(map(float, parts[1].split(',')))
            
            if len(coords) != 4:
                raise ValueError('Tọa độ phải có 4 giá trị: x1,y1,x2,y2')
            
            x1, x2 = sorted([coords[0], coords[2]])
            y1, y2 = sorted([coords[1], coords[3]])
            
            timestamp = str(int(time.time()))
            field_name = f"Signature_{self.username}_{timestamp}"
            
            return SigFieldSpec(
                sig_field_name=field_name,
                on_page=page,
                box=(x1, y1, x2, y2)
            )
        except (ValueError, IndexError) as e:
            raise ValueError(f'Lỗi xử lý tọa độ chữ ký: {str(e)}')
    
    def sign_pdf(self, input_path, output_path, field_spec, 
                 reason='Signed', location='', use_timestamp=True, invisible=False):
        
        trust_roots = self._load_trust_roots()
        
        try:
            signer_obj = signers.SimpleSigner.load_pkcs12(
                self.p12_tmp.name, 
                passphrase=self.passphrase.encode('utf-8'),
                ca_chain_files=None,
                other_certs=trust_roots
            )
        except (AttributeError, TypeError):
            signer_obj = signers.SimpleSigner.load_pkcs12(
                self.p12_tmp.name, 
                passphrase=self.passphrase.encode('utf-8')
            )
            if hasattr(signer_obj, 'cert_registry') and trust_roots:
                signer_obj.cert_registry.extend(trust_roots)
        
        signature_meta = signers.PdfSignatureMetadata(
            field_name=field_spec.sig_field_name,
            name=self.username,
            reason=reason,
            location=location if location else 'Vietnam',
            subfilter=ph_fields.SigSeedSubFilter.PADES,
        )
        
        timestamper = None
        if use_timestamp:
            timestamper = self._get_timestamper()
        
        trust_roots = self._load_trust_roots()
        validation_context = None
        if trust_roots:
            from pyhanko_certvalidator import ValidationContext
            all_chain_certs = trust_roots
            validation_context = ValidationContext(
                trust_roots=trust_roots,
                other_certs=all_chain_certs,
                allow_fetching=False,
                revocation_mode='soft-fail',
                weak_hash_algos=set()
            )
        
        with open(input_path, 'rb') as inf:
            pdf_writer = IncrementalPdfFileWriter(inf)
            
            logger.debug(f"Signing PDF with field: {field_spec.sig_field_name} "
                  f"on page {field_spec.on_page}, box {field_spec.box}")
            
            with open(output_path, 'wb') as outf:
                if invisible:
                    logger.debug("Adding invisible signature (no field)")
                    signers.sign_pdf(
                        pdf_writer,
                        signature_meta=signature_meta,
                        signer=signer_obj,
                        timestamper=timestamper,
                        existing_fields_only=False,
                        output=outf
                    )
                else:
                    signers.sign_pdf(
                        pdf_writer,
                        signature_meta=signature_meta,
                        signer=signer_obj,
                        timestamper=timestamper,
                        new_field_spec=field_spec,
                        output=outf
                    )
        
        if not os.path.exists(output_path) or os.path.getsize(output_path) == 0:
            raise ValueError('Signed PDF is empty or not created')
    
    def _get_timestamper(self):
        
        tsa_urls = [
            getattr(settings, 'TSA_URL', None),
            'http://timestamp.digicert.com',
            'http://timestamp.sectigo.com',
            'http://time.certum.pl'
        ]
        
        for tsa_url in tsa_urls:
            if tsa_url:
                try:
                    timestamper = ph_timestamps.HTTPTimeStamper(tsa_url)
                    return timestamper
                except Exception:
                    continue
        
        return None
    
    def _load_trust_roots(self):
        trust_roots = []
        
        try:
            from asn1crypto import x509 as asn1_x509, pem as asn1_pem
            
            root_dir = os.path.join(settings.BASE_DIR, 'certs', 'root-ca')
            int_dir = os.path.join(settings.BASE_DIR, 'certs', 'intermediate-ca', 'certs')
            
            for cert_dir in [root_dir, int_dir]:
                if os.path.isdir(cert_dir):
                    for fn in os.listdir(cert_dir):
                        if fn.lower().endswith(('.crt', '.pem')):
                            try:
                                with open(os.path.join(cert_dir, fn), 'rb') as cf:
                                    data = cf.read()
                                try:
                                    cert = asn1_x509.Certificate.load(data)
                                except ValueError:
                                    _, _, der = asn1_pem.unarmor(data)
                                    cert = asn1_x509.Certificate.load(der)
                                trust_roots.append(cert)
                            except Exception:
                                continue
        except Exception:
            trust_roots = []
        
        return trust_roots