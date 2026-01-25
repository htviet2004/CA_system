"""
PDF signing and verification views.

SECURITY NOTE: CSRF temporarily disabled for testing.
TODO: Re-enable CSRF protection before production deployment.
"""

import logging
import tempfile
import os
import traceback
import hashlib

from django.conf import settings
from django.http import JsonResponse, FileResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate
from django.contrib.auth.decorators import login_required
from datetime import datetime

from .certificate_service import CertificateService
from .pdf_signer import PDFSigner
from .pdf_verifier import PDFVerifier
from .pdf_stamp import PDFStampService
from .utils import find_pyhanko_executable
from .validators import validate_pdf_upload, validate_signature_position
from .constants import SIGNING_DEFAULT_REASON, SIGNING_DEFAULT_LOCATION
from usermanage.models import UserProfile
from usercerts.models import UserCert, SigningHistory

logger = logging.getLogger(__name__)


def _find_pyhanko(preferred=None):
    return find_pyhanko_executable(preferred)


def _get_client_ip(request):
    """Extract client IP from request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')


def _record_signing_history(user, uploaded_file, signed_content, reason, request, certificate=None):
    """
    Record signing action in SigningHistory.
    Called after successful PDF signing.
    
    Note: location field is deprecated and no longer collected.
    """
    try:
        # Compute hash of signed document
        doc_hash = hashlib.sha256(signed_content).hexdigest()
        
        # Get certificate if not provided
        if not certificate:
            certificate = UserCert.objects.filter(
                user=user, 
                active=True
            ).order_by('-created_at').first()
        
        SigningHistory.objects.create(
            user=user,
            certificate=certificate,
            document_name=uploaded_file.name or 'unknown.pdf',
            document_hash=doc_hash,
            document_size=len(signed_content),
            reason=reason,
            location='',  # Deprecated - kept for backward compatibility
            status='valid',
            ip_address=_get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')[:512],
        )
        logger.info(f"Recorded signing history: {uploaded_file.name} by {user.username}")
    except Exception as e:
        # SECURITY: Log but don't fail the signing operation
        logger.error(f"Failed to record signing history: {e}")


@csrf_exempt  # TODO: Re-enable CSRF for production
@login_required
@require_http_methods(["POST"])
def sign_file(request):
    """
    Sign a PDF file with user's certificate.
    
    NOTE: CSRF temporarily disabled for testing.
    """
    
    try:
        uploaded = request.FILES.get('file')
        if not uploaded:
            return JsonResponse({'error': 'no file uploaded'}, status=400)
        
        # SECURITY: Validate uploaded file
        try:
            validate_pdf_upload(uploaded)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

        reason = request.POST.get('reason', SIGNING_DEFAULT_REASON)
        position = request.POST.get('position', '')
        
        # SECURITY: Use session-authenticated user (already enforced by @login_required)
        user = request.user
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
            
            logger.debug(f"Adding visual stamp at page {page_num}, box {box}")
            
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
            
            logger.debug(f"Visual stamp added to: {stamped_path}")
            
            with PDFSigner(p12_data, passphrase, username) as signer:
                x1, y1, x2, y2 = box
                invisible_position = f"{page_num}/{x1},{y1},{x1+1},{y1+1}"
                field_spec = signer.parse_position(invisible_position)
                
                signer.sign_pdf(
                    stamped_path,
                    out_path,
                    field_spec,
                    reason=reason,
                    location='',  # Deprecated - kept for API compatibility
                    invisible=True
                )
            
            logger.debug(f"Signature added, output: {out_path}")
            
            if not os.path.exists(out_path):
                raise ValueError(f'Signed PDF not created: {out_path}')
            
            if os.path.getsize(out_path) == 0:
                raise ValueError('Signed PDF is empty')
            
            logger.debug(f"Output file validated: {os.path.getsize(out_path)} bytes")
            
            # Record signing history
            with open(out_path, 'rb') as signed_file:
                signed_content = signed_file.read()
            
            # Get user's active certificate for history
            user_cert = UserCert.objects.filter(
                user=user, 
                active=True
            ).order_by('-created_at').first()
            
            _record_signing_history(
                user=user,
                uploaded_file=uploaded,
                signed_content=signed_content,
                reason=reason,
                request=request,
                certificate=user_cert
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
                logger.warning(f"Cleanup error: {e}")
            
            return resp
        
        except ValueError as e:
            logger.warning(f"Validation error: {e}")
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
            logger.error(f"Signing failed: {type(e).__name__}: {str(e)}", exc_info=True)
            
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
        logger.error(f"Unexpected error in sign_file: {exc}")
        traceback.print_exc()
        return JsonResponse({
            'error': 'Internal server error',
            'details': str(exc)
        }, status=500)


@csrf_exempt  # TODO: Re-enable CSRF for production
@require_http_methods(["POST"])
def verify_pdf(request):
    """
    Verify signatures in a PDF file.
    
    NOTE: CSRF temporarily disabled for testing.
    Public endpoint for signature verification.
    """
    uploaded = request.FILES.get('file')
    if not uploaded:
        return JsonResponse({'error': 'No file uploaded'}, status=400)
    
    # SECURITY: Validate uploaded file
    try:
        validate_pdf_upload(uploaded)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)

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
        logger.error(f"Verification failed: {e}")
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


@csrf_exempt  # TODO: Re-enable CSRF for production
@require_http_methods(["POST"])
def get_pdf_info(request):
    """
    Get information about a PDF file.
    
    NOTE: CSRF temporarily disabled for testing.
    """
    uploaded = request.FILES.get('file')
    if not uploaded:
        return JsonResponse({'error': 'No file uploaded'}, status=400)
    
    # SECURITY: Validate uploaded file
    try:
        validate_pdf_upload(uploaded)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)
    
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


# SECURITY: Removed _authenticate_user() - use @login_required decorator instead
# POST-based authentication is vulnerable to CSRF and credential leakage
