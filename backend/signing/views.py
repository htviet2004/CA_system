
from django.conf import settings
from django.http import JsonResponse, FileResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate
from django.utils import timezone
import tempfile
import os
import traceback

from .certificate_service import CertificateService
from .pdf_signer import PDFSigner
from .pdf_verifier import PDFVerifier
from .pdf_stamp import PDFStampService
from .cache_manager import signed_pdf_cache
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
            
            # Lưu vào cache (metadata + file)
            signer_name = text_config.get('signer_name', '')
            title = text_config.get('title', '')
            custom_text = text_config.get('custom_text', '')
            
            signed_pdf_cache.save(
                user=user,
                pdf_path=out_path,
                original_filename=uploaded.name or 'signed.pdf',
                signer_name=signer_name,
                title=title,
                custom_text=custom_text,
                reason=reason,
                location=location
            )
            
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


@csrf_exempt
def get_cached_pdf(request):
    """
    Lấy PDF đã ký từ cache theo ID
    
    GET /api/sign/cached-pdf/?pdf_id=<pdf_id>
    """
    if request.method != 'GET':
        return JsonResponse({'error': 'GET only'}, status=405)
    
    user = _authenticate_user(request)
    if not user:
        return JsonResponse({'error': 'authentication required'}, status=401)
    
    pdf_id = request.GET.get('pdf_id')
    if not pdf_id:
        return JsonResponse({'error': 'Missing pdf_id parameter'}, status=400)
    
    try:
        pdf_path, filename = signed_pdf_cache.get_pdf_file(user, pdf_id)
        
        if not pdf_path:
            return JsonResponse({
                'error': 'PDF not found or access denied',
                'available': False
            }, status=404)
        
        # Mở file nhưng KHÔNG dùng with context manager
        # vì FileResponse cần file vẫn mở để đọc dữ liệu
        f = open(pdf_path, 'rb')
        response = FileResponse(
            f,
            as_attachment=True,
            filename=filename
        )
        # Django sẽ tự đóng file sau khi ghi response xong
        return response
    except Exception as e:
        print(f"[ERROR] Error serving cached PDF for {user.username}: {e}")
        return JsonResponse({
            'error': 'Error reading cached PDF',
            'available': False
        }, status=500)


@csrf_exempt
def check_cached_pdf(request):
    """
    Lấy danh sách PDF đang cached (chưa hết hạn) của user
    
    GET /api/sign/check-cache/
    """
    if request.method != 'GET':
        return JsonResponse({'error': 'GET only'}, status=405)
    
    user = _authenticate_user(request)
    if not user:
        return JsonResponse({'error': 'authentication required'}, status=401)
    
    active_pdfs = signed_pdf_cache.get_active_pdfs(user)
    from datetime import datetime
    
    pdfs_response = []
    for pdf in active_pdfs:
        # So sánh aware datetime với aware datetime
        elapsed = (timezone.now() - pdf.created_at).total_seconds()
        remaining = max(0, 3600 - int(elapsed))
        print(f"[API DEBUG] check_cached_pdf - {pdf.pdf_id}, created_at: {pdf.created_at}, now: {timezone.now()}, elapsed: {elapsed}s, remaining: {remaining}s")
        pdfs_response.append({
            'pdf_id': pdf.pdf_id,
            'filename': pdf.filename,
            'signed_at': pdf.signed_at.isoformat(),
            'created_at': pdf.created_at.isoformat(),
            'remaining_seconds': remaining
        })
    
    return JsonResponse({
        'available': len(active_pdfs) > 0,
        'count': len(active_pdfs),
        'pdfs': pdfs_response
    })


@csrf_exempt
def clear_cached_pdf(request):
    """
    Xóa toàn bộ PDF cached của user
    
    POST /api/sign/clear-cache/
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'POST only'}, status=405)
    
    user = _authenticate_user(request)
    if not user:
        return JsonResponse({'error': 'authentication required'}, status=401)
    
    signed_pdf_cache.delete_all(user)
    
    return JsonResponse({'success': True, 'message': 'All cached PDFs cleared'})


@csrf_exempt
def verify_cache_status(request):
    """
    Verify cache status: check TTL + file existence + cleanup expired
    
    GET /api/sign/verify-cache-status/
    """
    if request.method != 'GET':
        return JsonResponse({'error': 'GET only'}, status=405)
    
    user = _authenticate_user(request)
    if not user:
        return JsonResponse({'error': 'authentication required'}, status=401)
    
    stats = signed_pdf_cache.verify_cache_status(user)
    
    return JsonResponse({
        'success': True,
        'stats': stats,
        'message': f"Cache status: {stats['active']} còn hạn, {stats['expired_ttl']} hết thời gian, {stats['file_missing']} mất file"
    })


@csrf_exempt
def get_signed_pdfs_log(request):
    """
    Lấy toàn bộ log PDF đã ký của user (bao gồm đã hết hạn)
    
    GET /api/sign/signed-pdfs-log/
    """
    if request.method != 'GET':
        return JsonResponse({'error': 'GET only'}, status=405)
    
    user = _authenticate_user(request)
    if not user:
        return JsonResponse({'error': 'authentication required'}, status=401)
    
    all_pdfs = signed_pdf_cache.get_all_pdfs_log(user)
    
    pdfs_response = []
    for pdf in all_pdfs:
        # So sánh aware datetime với aware datetime
        elapsed = (timezone.now() - pdf.created_at).total_seconds()
        remaining = max(0, 3600 - int(elapsed))
        print(f"[API DEBUG] get_signed_pdfs_log - {pdf.pdf_id}, created_at: {pdf.created_at}, now: {timezone.now()}, elapsed: {elapsed}s, remaining: {remaining}s, is_cached: {pdf.is_cached}")
        pdfs_response.append({
            'pdf_id': pdf.pdf_id,
            'filename': pdf.filename,
            'signed_at': pdf.signed_at.isoformat(),
            'created_at': pdf.created_at.isoformat(),
            'is_cached': pdf.is_cached,
            'remaining_seconds': remaining
        })
    
    return JsonResponse({
        'count': len(all_pdfs),
        'pdfs': pdfs_response
    })


def _authenticate_user(request):
    
    if hasattr(request, 'user') and request.user.is_authenticated:
        return request.user
    
    username = request.POST.get('username') or request.GET.get('username')
    password = request.POST.get('password') or request.GET.get('password')
    
    if username and password:

        return authenticate(username=username, password=password)
    
    return None
