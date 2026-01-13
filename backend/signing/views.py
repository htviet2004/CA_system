
from django.conf import settings
from django.http import JsonResponse, FileResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate
import tempfile
import os
import traceback

from .certificate_service import CertificateService
from .pdf_signer import PDFSigner
from .pdf_verifier import PDFVerifier
from .pdf_stamp import PDFStampService
from .utils import find_pyhanko_executable
from datetime import datetime
from usermanage.models import UserProfile


def _find_pyhanko(preferred=None):
    return find_pyhanko_executable(preferred)


@csrf_exempt
def sign_file(request):
    
    try:
        if request.method == 'OPTIONS':
            return JsonResponse({'ok': True})

        if request.method != 'POST':
            return JsonResponse({'error': 'POST only'}, status=405)

        uploaded = request.FILES.get('file')
        if not uploaded:
            return JsonResponse({'error': 'no file uploaded'}, status=400)

        reason = request.POST.get('reason', 'Signed')
        location = request.POST.get('location', '')
        position = request.POST.get('position', '')
        
        user = _authenticate_user(request)
        if not user:
            return JsonResponse({'error': 'authentication required'}, status=401)
        
        username = user.username
        
        cert_service = CertificateService()
        enc_p12, enc_pass = cert_service.find_user_certificate(user, username)
        
        if not enc_p12 or not enc_pass:
            try:
                password = request.POST.get('password')
                enc_p12, enc_pass = cert_service.auto_issue_certificate(
                    username, password
                )
            except Exception as e:
                return JsonResponse({
                    'error': 'user p12 not found; auto-issue failed',
                    'detail': str(e)
                }, status=500)
        
        if not enc_p12 or not enc_pass:
            return JsonResponse({
                'error': 'no user certificate available'
            }, status=400)
        
        p12_data, passphrase = cert_service.decrypt_certificate(enc_p12, enc_pass)
        
        in_tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
        try:
            for chunk in uploaded.chunks():
                in_tmp.write(chunk)
            in_tmp.flush()
            in_path = in_tmp.name
        finally:
            in_tmp.close()
        
        out_fd, out_path = tempfile.mkstemp(suffix='.pdf')
        os.close(out_fd)
        
        stamped_fd, stamped_path = tempfile.mkstemp(suffix='_stamped.pdf')
        os.close(stamped_fd)
        
        try:
            with PDFSigner(p12_data, passphrase, username) as temp_signer:
                field_spec_temp = temp_signer.parse_position(position)
                page_num = field_spec_temp.on_page
                box = field_spec_temp.box
            
            print(f"[STAMP] Adding visual stamp at page {page_num}, box {box}")
            
            import json
            text_config = None
            
            try:
                profile = UserProfile.objects.get(user=user)
                signer_name = request.POST.get('signer_name', '').strip() or getattr(profile, 'full_name', '') or username
                department = getattr(profile, 'department', '') or ''
                title = request.POST.get('title', '').strip() or getattr(profile, 'role', '') or ''
            except UserProfile.DoesNotExist:
                signer_name = request.POST.get('signer_name', '').strip() or username
                department = ''
                title = request.POST.get('title', '').strip()
            
            custom_text = request.POST.get('custom_text', '').strip()
            
            text_config = {
                'signer_name': signer_name,
                'department': department,
                'title': title,
                'custom_text': custom_text
            }
            
            PDFStampService.add_stamp_to_pdf(
                input_pdf_path=in_path,
                output_pdf_path=stamped_path,
                page_num=page_num,
                box=box,
                username=username,
                timestamp=datetime.now(),
                style='dut_professional',
                text_config=text_config
            )
            
            print(f"[STAMP] Visual stamp added to: {stamped_path}")
            
            with PDFSigner(p12_data, passphrase, username) as signer:
                x1, y1, x2, y2 = box
                invisible_position = f"{page_num}/{x1},{y1},{x1+1},{y1+1}"
                field_spec = signer.parse_position(invisible_position)
                
                signer.sign_pdf(
                    stamped_path,
                    out_path,
                    field_spec,
                    reason=reason,
                    location=location,
                    invisible=True
                )
            
            print(f"[SIGN] Signature added, output: {out_path}")
            
            if not os.path.exists(out_path):
                raise ValueError(f'Signed PDF not created: {out_path}')
            
            if os.path.getsize(out_path) == 0:
                raise ValueError('Signed PDF is empty')
            
            print(f"[SIGN] Output file validated: {os.path.getsize(out_path)} bytes")
            
            resp = FileResponse(
                open(out_path, 'rb'),
                as_attachment=True,
                filename=uploaded.name or 'signed.pdf'
            )
            
            try:
                os.unlink(in_path)
                os.unlink(stamped_path)
            except Exception as e:
                print(f"[WARN] Cleanup error: {e}")
            
            return resp
        
        except ValueError as e:
            print(f"[ERROR] Validation error: {e}")
            try:
                os.unlink(in_path)
                if os.path.exists(stamped_path):
                    os.unlink(stamped_path)
                if os.path.exists(out_path):
                    os.unlink(out_path)
            except Exception:
                pass
            
            return JsonResponse({'error': str(e)}, status=400)
        
        except Exception as e:
            print(f"[ERROR] Signing failed: {type(e).__name__}: {str(e)}")
            traceback.print_exc()
            
            try:
                os.unlink(in_path)
                if os.path.exists(stamped_path):
                    os.unlink(stamped_path)
                if os.path.exists(out_path):
                    os.unlink(out_path)
            except Exception:
                pass
            
            return JsonResponse({
                'error': 'Signing failed',
                'details': str(e)
            }, status=500)
    
    except Exception as exc:
        print(f"[ERROR] Unexpected error in sign_file: {exc}")
        traceback.print_exc()
        return JsonResponse({
            'error': 'Internal server error',
            'details': str(exc)
        }, status=500)


@csrf_exempt
def verify_pdf(request):
    
    if request.method != 'POST':
        return JsonResponse({'error': 'POST only'}, status=405)

    uploaded = request.FILES.get('file')
    if not uploaded:
        return JsonResponse({'error': 'No file uploaded'}, status=400)

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
    try:
        for chunk in uploaded.chunks():
            tmp.write(chunk)
        tmp.flush()
        tmp_path = tmp.name
    finally:
        tmp.close()

    try:
        verifier = PDFVerifier()
        result = verifier.verify(tmp_path)
        return JsonResponse(result)
    
    except Exception as e:
        print(f"[ERROR] Verification failed: {e}")
        traceback.print_exc()
        return JsonResponse({
            'error': str(e),
            'valid': False,
            'signatures': [],
            'signature_count': 0
        }, status=500)
    
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


@csrf_exempt
def get_pdf_info(request):
    
    if request.method != 'POST':
        return JsonResponse({'error': 'POST only'}, status=405)
    
    uploaded = request.FILES.get('file')
    if not uploaded:
        return JsonResponse({'error': 'No file uploaded'}, status=400)
    
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
    try:
        for chunk in uploaded.chunks():
            tmp.write(chunk)
        tmp.flush()
        tmp_path = tmp.name
    finally:
        tmp.close()

    try:
        from pyhanko.pdf_utils.reader import PdfFileReader
        
        with open(tmp_path, 'rb') as f:
            reader = PdfFileReader(f)
            info = {
                'page_count': None,
                'has_signatures': False,
                'signature_fields': [],
                'metadata': {}
            }
            
            try:
                pages = reader.root.get('/Pages')
                if pages and '/Kids' in pages:
                    info['page_count'] = len(pages['/Kids'])
            except Exception:
                info['page_count'] = None

            if '/AcroForm' in reader.root and '/Fields' in reader.root['/AcroForm']:
                fields = reader.root['/AcroForm']['/Fields']
                for field in fields:
                    field_obj = field.get_object()
                    if '/V' in field_obj:
                        info['has_signatures'] = True
                        field_name = field_obj.get('/T', 'Unknown')
                        info['signature_fields'].append(str(field_name))

            if '/Info' in reader.root:
                metadata = reader.root['/Info']
                for key in ['/Title', '/Author', '/Subject', '/Creator', '/Producer']:
                    if key in metadata:
                        info['metadata'][key[1:].lower()] = str(metadata[key])

        return JsonResponse(info)
    
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
    
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


def _authenticate_user(request):
    
    if hasattr(request, 'user') and request.user.is_authenticated:
        return request.user
    
    username = request.POST.get('username')
    password = request.POST.get('password')
    
    if username and password:
        return authenticate(username=username, password=password)
    
    return None
