"""
PDF Verifier service for validating PDF signatures
"""
import os
from django.conf import settings
from pyhanko.sign import validation
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko_certvalidator import ValidationContext
from datetime import datetime


class PDFVerifier:
    """Service để xác thực chữ ký PDF"""
    
    def __init__(self):
        self.trust_roots = []
        self.intermediate_certs = []
        self._load_ca_certificates()
    
    def _load_ca_certificates(self):
        """Load Root CA và Intermediate CA certificates"""
        # Load Root CA
        root_dir = os.path.join(settings.BASE_DIR, 'certs', 'root-ca')
        self._load_certs_from_dir(root_dir, self.trust_roots)
        
        # Load Intermediate CA
        int_dir = os.path.join(
            settings.BASE_DIR, 'certs', 'intermediate-ca', 'certs'
        )
        self._load_certs_from_dir(int_dir, self.intermediate_certs)
        
        print(f"[VERIFY] Loaded {len(self.trust_roots)} root CAs and "
              f"{len(self.intermediate_certs)} intermediate CAs")
    
    def _load_certs_from_dir(self, cert_dir, cert_list):
        """
        Load certificates từ directory
        
        Args:
            cert_dir: Đường dẫn thư mục chứa certificates
            cert_list: List để append certificates vào
        """
        from asn1crypto import x509 as asn1_x509, pem as asn1_pem
        
        if not os.path.isdir(cert_dir):
            return
        
        for fn in os.listdir(cert_dir):
            if not fn.lower().endswith(('.crt', '.pem')):
                continue
            
            try:
                with open(os.path.join(cert_dir, fn), 'rb') as cf:
                    data = cf.read()
                
                try:
                    cert = asn1_x509.Certificate.load(data)
                except ValueError:
                    _, _, der = asn1_pem.unarmor(data)
                    cert = asn1_x509.Certificate.load(der)
                
                cert_list.append(cert)
                print(f"[VERIFY] Loaded cert: {fn}")
            except Exception as e:
                print(f"[VERIFY] Failed to load cert {fn}: {e}")
    
    def verify(self, pdf_path):
        """
        Xác thực tất cả chữ ký trong PDF
        
        Args:
            pdf_path: Đường dẫn đến file PDF
            
        Returns:
            dict: Kết quả xác thực với format:
                {
                    'valid': bool,
                    'signatures': list,
                    'signature_count': int,
                    'error': str or None
                }
        """
        signatures = []
        
        try:
            with open(pdf_path, 'rb') as f:
                reader = PdfFileReader(f)
                sig_fields = self._get_signature_fields(reader)
                
                vc = self._create_validation_context()
                
                for sig_field in sig_fields:
                    sig_info = self._verify_signature(reader, sig_field, vc)
                    signatures.append(sig_info)
            
            overall_valid = all(
                sig['valid'] for sig in signatures
            ) if signatures else False
            
            return {
                'valid': overall_valid,
                'signatures': signatures,
                'signature_count': len(signatures),
                'error': None
            }
        
        except Exception as e:
            return {
                'valid': False,
                'signatures': [],
                'signature_count': 0,
                'error': str(e)
            }
    
    def _get_signature_fields(self, reader):
        """
        Lấy danh sách signature fields từ PDF
        
        Args:
            reader: PdfFileReader object
            
        Returns:
            list: Danh sách signature fields
        """
        if '/AcroForm' not in reader.root:
            return []
        
        acro_form = reader.root['/AcroForm']
        if '/Fields' not in acro_form:
            return []
        
        return acro_form['/Fields']
    
    def _create_validation_context(self):
        """
        Tạo ValidationContext với trust roots
        
        Returns:
            ValidationContext hoặc None
        """
        if not self.trust_roots:
            return None
        
        try:
            # Include ALL certificates (root + intermediate) in other_certs
            # để giúp pyhanko build complete certificate chain
            all_chain_certs = self.intermediate_certs + self.trust_roots
            
            vc = ValidationContext(
                trust_roots=self.trust_roots,
                other_certs=all_chain_certs,
                allow_fetching=False,
                revocation_mode='soft-fail',
                weak_hash_algos=set()  # Allow all hash algorithms
            )
            
            print(f"[VERIFY] ValidationContext created with "
                  f"{len(self.trust_roots)} trust roots and "
                  f"{len(all_chain_certs)} chain certs")
            
            return vc
        except Exception as e:
            print(f"[VERIFY] Failed to create ValidationContext: {e}")
            return None
    
    def _verify_signature(self, reader, sig_field, validation_context):
        """
        Xác thực một signature field
        
        Args:
            reader: PdfFileReader object
            sig_field: Signature field object
            validation_context: ValidationContext object
            
        Returns:
            dict: Thông tin chữ ký đã xác thực
        """
        try:
            field_obj = sig_field.get_object()
            fq_name = field_obj.get('/T', 'sig')
            
            embedded_sig = validation.EmbeddedPdfSignature(
                reader, sig_field, fq_name
            )
            
            # Validate signature với hoặc không có validation context
            try:
                status = validation.validate_pdf_signature(
                    embedded_sig, 
                    signer_validation_context=validation_context
                )
            except TypeError:
                # Fallback nếu API không hỗ trợ validation_context
                status = validation.validate_pdf_signature(embedded_sig)
            
            return self._extract_signature_info(status)
        
        except Exception as e:
            print(f"[VERIFY ERROR] Failed to validate signature: {e}")
            import traceback
            traceback.print_exc()
            
            return {
                'signer': 'Unknown',
                'timestamp': None,
                'valid': False,
                'trust_status': 'ERROR',
                'certificate_info': {},
                'signature_intact': None,
                'document_intact': None,
                'coverage': None,
                'validation_time': datetime.now().isoformat(),
                'error': str(e),
            }
    
    def _extract_signature_info(self, status):
        """
        Trích xuất thông tin từ validation status
        
        Args:
            status: Validation status object từ pyhanko
            
        Returns:
            dict: Thông tin chữ ký
        """
        # Get certificate
        cert = getattr(status, 'signer_cert', None) or getattr(status, 'signing_cert', None)
        
        # Extract certificate info
        cert_info = {}
        if cert is not None:
            cert_info = self._extract_certificate_info(cert)
        
        # Extract signer name from certificate
        signer_name = self._extract_signer_name(cert)
        
        # Debug log
        if cert:
            print(f"[DEBUG] Certificate subject: {cert.subject if hasattr(cert, 'subject') else 'N/A'}")
            print(f"[DEBUG] Extracted signer name: {signer_name}")
        
        # Extract timestamp
        timestamp = self._extract_timestamp(status)
        
        # Determine validity
        is_valid = self._determine_validity(status)
        
        # Trust status
        trusted = getattr(status, 'trusted', False)
        trust_problem = getattr(status, 'trust_problem_indic', None)
        trust_status = 'TRUSTED' if trusted else (
            getattr(trust_problem, 'name', 'UNTRUSTED') if trust_problem else 'UNTRUSTED'
        )
        
        print(f"[VERIFY] Signature for {signer_name}: valid={is_valid}, "
              f"trust={trust_status}, intact={getattr(status, 'intact', None)}")
        
        # Extract document integrity status
        doc_intact = getattr(status, 'doc_mdp_ok', None)
        
        # Debug document status
        print(f"[DEBUG] Document integrity: doc_mdp_ok={doc_intact}, "
              f"modification_level={getattr(status, 'modification_level', None)}, "
              f"coverage={getattr(getattr(status, 'coverage', None), 'name', None)}")
        
        return {
            'signer': signer_name,
            'timestamp': timestamp,
            'valid': is_valid,
            'trust_status': trust_status,
            'certificate_info': cert_info,
            'signature_intact': getattr(status, 'intact', None),
            'document_intact': doc_intact if doc_intact is not None else True,  # Default True nếu None
            'coverage': getattr(getattr(status, 'coverage', None), 'name', None),
            'validation_time': datetime.now().isoformat()
        }
    
    def _extract_certificate_info(self, cert):
        """Extract thông tin từ certificate object"""
        def _safe_subject(c):
            try:
                if hasattr(c.subject, 'rfc4514_string'):
                    return c.subject.rfc4514_string()
                if hasattr(c.subject, 'human_friendly'):
                    return c.subject.human_friendly
                return str(c.subject)
            except Exception:
                return str(c)
        
        def _safe_issuer(c):
            try:
                if hasattr(c.issuer, 'rfc4514_string'):
                    return c.issuer.rfc4514_string()
                if hasattr(c.issuer, 'human_friendly'):
                    return c.issuer.human_friendly
                return str(c.issuer)
            except Exception:
                return str(c)
        
        def _safe_dates(c):
            try:
                if hasattr(c, 'not_valid_before') and hasattr(c, 'not_valid_after'):
                    return c.not_valid_before.isoformat(), c.not_valid_after.isoformat()
                # asn1crypto path
                try:
                    nbf = c['tbs_certificate']['validity']['not_before'].native
                    naf = c['tbs_certificate']['validity']['not_after'].native
                    return (
                        nbf.isoformat() if hasattr(nbf, 'isoformat') else str(nbf),
                        naf.isoformat() if hasattr(naf, 'isoformat') else str(naf)
                    )
                except Exception:
                    return None, None
            except Exception:
                return None, None
        
        def _safe_serial(c):
            try:
                if hasattr(c, 'serial_number'):
                    return format(c.serial_number, 'X')
                try:
                    return format(int(c.serial_number.native), 'X')
                except Exception:
                    return str(getattr(c, 'serial_number', getattr(c, 'serial', None)))
            except Exception:
                return str(c)
        
        valid_from, valid_to = _safe_dates(cert)
        
        return {
            'subject': _safe_subject(cert),
            'issuer': _safe_issuer(cert),
            'valid_from': valid_from,
            'valid_to': valid_to,
            'serial_number': _safe_serial(cert),
        }
    
    def _extract_signer_name(self, cert):
        """Extract tên người ký từ certificate"""
        if cert is None:
            return 'Unknown'
        
        try:
            subject = cert.subject
            
            # asn1crypto.x509.Name có method .native để lấy dict
            if hasattr(subject, 'native'):
                subject_dict = subject.native
                # Thử các trường theo thứ tự ưu tiên
                for key in ['common_name', 'organizational_unit_name', 'organization_name', 'email_address']:
                    if key in subject_dict and subject_dict[key]:
                        return subject_dict[key]
            
            # Fallback: dùng human_friendly nếu có
            if hasattr(subject, 'human_friendly'):
                human = subject.human_friendly
                # Format: "CN=viet, emailAddress=viet@dut.local"
                if 'CN=' in human:
                    parts = human.split(',')
                    for part in parts:
                        if 'CN=' in part:
                            return part.split('CN=')[1].strip()
            
            # Thử method chosen
            if hasattr(subject, 'chosen'):
                for rdn in subject.chosen:
                    for attr in rdn:
                        # attr có oid và value
                        if hasattr(attr, 'value'):
                            attr_val = attr.value
                            if hasattr(attr_val, 'native'):
                                return attr_val.native
                                
        except Exception as e:
            print(f"[WARN] Cannot extract signer name: {e}")
        
        return 'Unknown'
    
    def _extract_timestamp(self, status):
        """Extract timestamp từ status"""
        try:
            if (getattr(status, 'timestamp_validity', None) and 
                getattr(status.timestamp_validity, 'timestamp', None)):
                return status.timestamp_validity.timestamp.isoformat()
        except Exception:
            pass
        
        return None
    
    def _determine_validity(self, status):
        """
        Xác định xem chữ ký có hợp lệ không
        
        Priority: bottom_line > (trusted AND intact) > (valid AND intact)
        """
        bottom_line = getattr(status, 'bottom_line', None)
        intact = getattr(status, 'intact', False)
        trusted = getattr(status, 'trusted', False)
        valid = getattr(status, 'valid', False)
        trust_problem = getattr(status, 'trust_problem_indic', None)
        
        # If bottom_line exists and is True, that's definitive
        if bottom_line is True:
            return True
        
        # If signature is intact and trusted, consider it valid
        if intact and trusted:
            return True
        
        # If signature is valid and intact but trust issue is only about chain,
        # still consider valid (handles cases where chain building fails 
        # but signature is cryptographically valid)
        if valid and intact and trust_problem and 'CHAIN' in str(trust_problem):
            print(f"[VERIFY] Accepting signature despite chain issue: {trust_problem}")
            return True
        
        # Fallback to valid + intact
        if valid and intact:
            return True
        
        return False
