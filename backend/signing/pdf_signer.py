"""
PDF Signer service for signing PDF documents
"""
import os
import tempfile
import time
from datetime import datetime
from pyhanko.sign import signers, fields as ph_fields, timestamps as ph_timestamps
from pyhanko.sign.fields import SigFieldSpec
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.stamp import TextStampStyle
from django.conf import settings

# Optional imports for advanced styling
try:
    from pyhanko.pdf_utils import text as pdf_text
    HAS_TEXT_UTILS = True
except ImportError:
    HAS_TEXT_UTILS = False


class PDFSigner:
    """Service để ký PDF documents"""
    
    def __init__(self, p12_data, passphrase, username):
        """
        Initialize PDF Signer
        
        Args:
            p12_data: PKCS#12 certificate data (bytes)
            passphrase: Password for P12 (string)
            username: Username for signature field naming
        """
        self.p12_data = p12_data
        self.passphrase = passphrase
        self.username = username
        self.p12_tmp = None
        self.pass_tmp = None
    
    def __enter__(self):
        """Context manager để tự động cleanup temp files"""
        self.p12_tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.p12')
        self.p12_tmp.write(self.p12_data)
        self.p12_tmp.flush()
        self.p12_tmp.close()
        
        self.pass_tmp = tempfile.NamedTemporaryFile(
            delete=False, mode='w', suffix='.txt'
        )
        self.pass_tmp.write(self.passphrase)
        self.pass_tmp.flush()
        self.pass_tmp.close()
        
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Cleanup temp files"""
        try:
            if self.p12_tmp:
                os.unlink(self.p12_tmp.name)
            if self.pass_tmp:
                os.unlink(self.pass_tmp.name)
        except Exception:
            pass
    
    def parse_position(self, position_str):
        """
        Parse chuỗi position thành SigFieldSpec
        
        Args:
            position_str: Format "page/x1,y1,x2,y2" (e.g., "0/10,10,100,50")
            
        Returns:
            SigFieldSpec: pyHanko signature field specification
            
        Raises:
            ValueError: Nếu position_str không hợp lệ
        """
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
            
            # Normalize coordinates (ensure x1 < x2 and y1 < y2)
            x1, x2 = sorted([coords[0], coords[2]])
            y1, y2 = sorted([coords[1], coords[3]])
            
            # Generate unique field name with timestamp
            timestamp = str(int(time.time()))
            field_name = f"Signature_{self.username}_{timestamp}"
            
            return SigFieldSpec(
                sig_field_name=field_name,
                on_page=page,
                box=(x1, y1, x2, y2)
            )
        except (ValueError, IndexError) as e:
            raise ValueError(f'Lỗi xử lý tọa độ chữ ký: {str(e)}')
    
    def _create_signature_appearance(self):
        """
        Tạo signature appearance chuyên nghiệp với styling tùy chỉnh
        
        Returns:
            TextStampStyle object hoặc None nếu không thể tạo
        """
        try:
            # Màu sắc chuyên nghiệp
            BLUE_LIGHT = (0.87, 0.92, 0.98)   # #dbeafe
            BORDER_COLOR = (0.15, 0.39, 0.93) # #2563eb
            
            style_kwargs = {
                'background': BLUE_LIGHT,
                'border_width': 2,
                'stamp_text': (
                    '%(signer_name)s\n'
                    'Ky so: %(ts)s\n'
                    '-----------------\n'
                    'Ly do: %(reason)s\n'
                    'Vi tri: %(location)s'
                ),
                'border_color': BORDER_COLOR,
            }
            
            # Chỉ thêm text_box_style nếu có text utils
            if HAS_TEXT_UTILS:
                style_kwargs['text_box_style'] = pdf_text.TextBoxStyle(
                    font_size=9,
                    leading=11,
                    text_sep='\n'
                )
            
            return TextStampStyle(**style_kwargs)
        except Exception as e:
            print(f"[WARN] Cannot create custom appearance: {e}")
            return None
    
    def sign_pdf(self, input_path, output_path, field_spec, 
                 reason='Signed', location='', use_timestamp=True):
        """
        Ký PDF file
        
        Args:
            input_path: Đường dẫn file PDF đầu vào
            output_path: Đường dẫn file PDF đầu ra
            field_spec: SigFieldSpec object
            reason: Lý do ký
            location: Vị trí ký
            use_timestamp: Có sử dụng timestamp từ TSA không
            
        Raises:
            Exception: Nếu việc ký thất bại
        """
        # Load trust roots (CA certificates) để embed vào signature
        trust_roots = self._load_trust_roots()
        
        # Load signer từ P12 với certificate chain
        try:
            signer_obj = signers.SimpleSigner.load_pkcs12(
                self.p12_tmp.name, 
                passphrase=self.passphrase.encode('utf-8'),
                ca_chain_files=None,  # Sẽ dùng cert_registry
                other_certs=trust_roots  # Embed CA chain vào signature
            )
        except (AttributeError, TypeError):
            # Older pyhanko API fallback - không có other_certs param
            signer_obj = signers.SimpleSigner.load_pkcs12(
                self.p12_tmp.name, 
                passphrase=self.passphrase.encode('utf-8')
            )
            # Manually add CA chain
            if hasattr(signer_obj, 'cert_registry') and trust_roots:
                signer_obj.cert_registry.extend(trust_roots)
        
        # Tạo custom signature appearance
        try:
            stamp_style = self._create_signature_appearance()
        except Exception as e:
            print(f"[WARN] Could not create custom appearance: {e}. Using default.")
            stamp_style = None
        
        # Tạo signature metadata với PAdES compliance
        signature_meta = signers.PdfSignatureMetadata(
            field_name=field_spec.sig_field_name,
            name=self.username,
            reason=reason,
            location=location if location else 'Vietnam',
            subfilter=ph_fields.SigSeedSubFilter.PADES,
            # Thêm custom appearance nếu tạo thành công
            **({
                'stamp_style': stamp_style,
                'use_pades_lta': True
            } if stamp_style else {})
        )
        
        # Attach a Time Stamp Authority (TSA) for trusted timestamps
        timestamper = None
        if use_timestamp:
            timestamper = self._get_timestamper()
        
        # Load trust roots for validation info embedding
        trust_roots = self._load_trust_roots()
        validation_context = None
        if trust_roots:
            from pyhanko_certvalidator import ValidationContext
            all_chain_certs = trust_roots  # Include all CAs
            validation_context = ValidationContext(
                trust_roots=trust_roots,
                other_certs=all_chain_certs,
                allow_fetching=False,
                revocation_mode='soft-fail',
                weak_hash_algos=set()
            )
        
        # Read PDF and sign it
        with open(input_path, 'rb') as inf:
            pdf_writer = IncrementalPdfFileWriter(inf)
            
            print(f"[SIGN] Signing PDF with field: {field_spec.sig_field_name} "
                  f"on page {field_spec.on_page}, box {field_spec.box}")
            
            with open(output_path, 'wb') as outf:
                signers.sign_pdf(
                    pdf_writer,
                    signature_meta=signature_meta,
                    signer=signer_obj,
                    timestamper=timestamper,
                    new_field_spec=field_spec,
                    output=outf
                )
        
        # Validate output file is non-empty
        if not os.path.exists(output_path) or os.path.getsize(output_path) == 0:
            raise ValueError('Signed PDF is empty or not created')
    
    def _get_timestamper(self):
        """
        Lấy timestamper từ TSA servers
        
        Returns:
            HTTPTimeStamper hoặc None
        """
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
                    # Test the connection (không thực sự gọi, chỉ khởi tạo)
                    return timestamper
                except Exception:
                    continue
        
        return None
    
    def _load_trust_roots(self):
        """
        Load root CA và intermediate CA certificates
        
        Returns:
            list: Danh sách certificate objects
        """
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
