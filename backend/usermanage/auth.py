"""
User authentication and registration views.

SECURITY: Authentication endpoints with proper CSRF protection.
"""

import logging
import re

from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.middleware.csrf import get_token
from django.views.decorators.csrf import csrf_exempt

from usercerts.models import UserCert
from signing.validators import validate_username
from signing.certificate_issuer import issue_user_certificate
from usermanage.models import UserProfile

logger = logging.getLogger(__name__)


def _validate_email(email):
    """Validate email format."""
    if not email:
        return ''
    email = email.strip()
    if len(email) > 254:
        raise ValueError("Email quá dài")
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        raise ValueError("Email không hợp lệ")
    return email


def _validate_phone(phone):
    """Validate phone number format."""
    if not phone:
        return ''
    phone = phone.strip()
    cleaned = re.sub(r'[\s\-\(\)]', '', phone)
    if not re.match(r'^\+?[0-9]{8,15}$', cleaned):
        raise ValueError("Số điện thoại không hợp lệ")
    return phone


@csrf_exempt  # SECURITY: Public registration endpoint, no user session yet
@require_http_methods(["POST"])
def register(request):
    """
    Register a new user with full profile information and issue certificate.
    
    SECURITY: Validates all inputs, uses centralized certificate issuer.
    Creates UserProfile automatically with submitted profile data.
    
    Required fields: username, password, full_name, email, department, role
    Optional fields: phone
    
    Note: @csrf_exempt is appropriate here as registration is a public endpoint
    requiring no prior authentication. Password validation prevents abuse.
    """
    username = request.POST.get('username')
    password = request.POST.get('password')
    full_name = request.POST.get('full_name', '').strip()
    email = request.POST.get('email', '').strip()
    phone = request.POST.get('phone', '').strip()
    department = request.POST.get('department', '').strip()
    role = request.POST.get('role', 'student').strip()
    
    # SECURITY: Validate username format
    try:
        username = validate_username(username)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)
    
    if not password:
        return JsonResponse({'error': 'Vui lòng nhập mật khẩu'}, status=400)
    
    # SECURITY: Minimum password length
    if len(password) < 8:
        return JsonResponse({'error': 'Mật khẩu phải có ít nhất 8 ký tự'}, status=400)
    
    # Validate required profile fields
    if not full_name:
        return JsonResponse({'error': 'Vui lòng nhập họ tên đầy đủ'}, status=400)
    
    if len(full_name) > 128:
        return JsonResponse({'error': 'Họ tên quá dài (tối đa 128 ký tự)'}, status=400)
    
    # Validate email
    try:
        email = _validate_email(email)
        if not email:
            return JsonResponse({'error': 'Vui lòng nhập email'}, status=400)
    except ValueError as e:
        return JsonResponse({'error': str(e)}, status=400)
    
    # Validate phone (optional)
    try:
        phone = _validate_phone(phone)
    except ValueError as e:
        return JsonResponse({'error': str(e)}, status=400)
    
    # Validate department
    if not department:
        return JsonResponse({'error': 'Vui lòng chọn khoa/phòng ban'}, status=400)
    
    if not UserProfile.is_valid_department(department):
        return JsonResponse({'error': 'Khoa/phòng ban không hợp lệ'}, status=400)
    
    # Validate role (SECURITY: prevent admin self-registration)
    if not role:
        return JsonResponse({'error': 'Vui lòng chọn vai trò'}, status=400)
    
    if role == 'admin':
        return JsonResponse({
            'error': 'Không thể tự đăng ký với vai trò Administrator. Liên hệ quản trị viên.'
        }, status=400)
    
    if not UserProfile.is_valid_role(role):
        return JsonResponse({'error': 'Vai trò không hợp lệ'}, status=400)
    
    if User.objects.filter(username=username).exists():
        return JsonResponse({'error': 'Tên đăng nhập đã tồn tại'}, status=400)
    
    # Check if email is already used
    if email and UserProfile.objects.filter(email=email).exists():
        return JsonResponse({'error': 'Email đã được sử dụng'}, status=400)
    
    # Create user
    user = User.objects.create_user(username=username, password=password, email=email)
    user.first_name = full_name
    user.save()
    
    # Create UserProfile automatically
    profile = UserProfile.objects.create(
        user=user,
        full_name=full_name,
        email=email,
        phone=phone,
        department=department,
        role=role
    )
    
    logger.info(f"Created profile for {username}: role={role}, department={department}")
    
    # Issue certificate using centralized service
    issued = False
    try:
        result = issue_user_certificate(username)
        
        if result.get('ok'):
            issued = True
            UserCert.objects.create(
                user=user, 
                common_name=full_name or username,  # Use full name as CN if available
                p12_enc_path=result.get('p12_enc_path', ''), 
                p12_pass_enc_path=result.get('p12_pass_enc_path', ''), 
                active=True
            )
        else:
            logger.warning(f"Certificate issuance failed for {username}: {result.get('error')}")
    except Exception as e:
        logger.error(f"Certificate issuance failed for {username}: {e}")

    # Audit log
    from usercerts.models import SecurityAuditLog
    SecurityAuditLog.log(
        category='AUTH',
        action='REGISTER',
        request=request,
        success=True,
        target_type='User',
        target_id=user.id,
        description=f"User registered: {username}, role={role}, department={department}, cert_issued={issued}",
        extra_data={
            'cert_issued': issued,
            'role': role,
            'department': department,
            'email': email
        }
    )
    
    logger.info(f"User registered: {username}, cert_issued: {issued}")
    return JsonResponse({
        'ok': True, 
        'username': username, 
        'cert_issued': issued,
        'profile_created': True
    })


@csrf_exempt  # SECURITY: First request has no session/CSRF token. Token returned in response.
@require_http_methods(["POST"])
def login_view(request):
    """
    Authenticate user and create Django session.
    
    SECURITY: Session cookie is HttpOnly and prevents XSS theft.
    CSRF token is returned for subsequent requests.
    Note: @csrf_exempt is safe here because login doesn't modify sensitive state
    until user is authenticated. Credential validation protects against CSRF.
    """
    from usercerts.models import SecurityAuditLog
    
    username = request.POST.get('username')
    password = request.POST.get('password')
    
    if not username or not password:
        return JsonResponse({'error': 'username and password required'}, status=400)
    
    user = authenticate(username=username, password=password)
    if not user:
        # SECURITY: Log failed login attempts
        logger.warning(f"Failed login attempt for username: {username}")
        SecurityAuditLog.log(
            category='AUTH',
            action='LOGIN_FAILED',
            request=request,
            success=False,
            severity='WARNING',
            description=f"Failed login attempt for username: {username}",
            extra_data={'attempted_username': username}
        )
        return JsonResponse({'error': 'invalid credentials'}, status=401)
    
    login(request, user)
    
    # Audit log successful login
    SecurityAuditLog.log(
        category='AUTH',
        action='LOGIN',
        request=request,
        user=user,
        success=True,
        target_type='User',
        target_id=user.id,
        description=f"User logged in: {username}"
    )
    
    logger.info(f"User logged in: {username}")
    
    # SECURITY: Return CSRF token for SPA clients
    return JsonResponse({
        'ok': True, 
        'username': username,
        'is_staff': user.is_staff,
        'is_active': user.is_active,
        'csrf_token': get_token(request)  # For frontend to use in subsequent requests
    })


@login_required
@require_http_methods(["POST"])
def issue_cert(request):
    """
    Issue a certificate for the authenticated user.
    
    SECURITY: Uses centralized certificate issuer with secure practices.
    """
    from usercerts.models import SecurityAuditLog
    
    # SECURITY: Use session-authenticated user
    user = request.user
    username = user.username
    common_name = request.POST.get('cn', username)
    
    # Validate common name
    try:
        from signing.validators import validate_common_name
        common_name = validate_common_name(common_name)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)
    
    # Use centralized certificate issuer
    result = issue_user_certificate(username, common_name=common_name)
    
    if not result.get('ok'):
        logger.error(f"Certificate issuance failed for {username}: {result.get('error')}")
        SecurityAuditLog.log(
            category='CERT',
            action='ISSUE_FAILED',
            request=request,
            user=user,
            success=False,
            severity='ERROR',
            target_type='Certificate',
            description=f"Certificate issuance failed for {username}",
            error_message=result.get('error', '')
        )
        return JsonResponse({'error': 'Certificate generation failed'}, status=500)
    
    try:
        uc = UserCert.objects.create(
            user=user,
            common_name=common_name,
            p12_enc_path=result.get('p12_enc_path', ''),
            p12_pass_enc_path=result.get('p12_pass_enc_path', ''),
            active=True,
        )
        logger.info(f"Certificate issued for user: {username}")
        
        SecurityAuditLog.log(
            category='CERT',
            action='ISSUE',
            request=request,
            user=user,
            success=True,
            target_type='Certificate',
            target_id=uc.id,
            description=f"Certificate issued for {username}"
        )
    except Exception as e:
        logger.error(f"Failed to create UserCert record: {e}")
        uc = None

    resp = {'ok': True}
    if uc:
        resp['usercert_id'] = uc.id
    return JsonResponse(resp)


def get_csrf_token(request):
    """
    Get CSRF token for frontend.
    
    SECURITY: This endpoint provides CSRF tokens for SPA clients.
    """
    return JsonResponse({'csrf_token': get_token(request)})


def get_current_user(request):
    """
    Return currently authenticated user info from Django session.
    
    SECURITY: Read-only endpoint, no CSRF required for GET.
    """
    if not request.user.is_authenticated:
        return JsonResponse({
            'authenticated': False,
            'csrf_token': get_token(request)  # Provide token for login form
        }, status=200)
    
    return JsonResponse({
        'authenticated': True,
        'username': request.user.username,
        'is_staff': request.user.is_staff,
        'is_active': request.user.is_active,
        'email': request.user.email or '',
        'csrf_token': get_token(request)
    })


@require_http_methods(["POST"])
def logout_view(request):
    """
    Logout user and destroy Django session.
    
    SECURITY: Requires CSRF token to prevent logout CSRF attacks.
    """
    from usercerts.models import SecurityAuditLog
    
    username = request.user.username if request.user.is_authenticated else 'anonymous'
    user = request.user if request.user.is_authenticated else None
    
    # Audit log before logout (so we still have the user info)
    SecurityAuditLog.log(
        category='AUTH',
        action='LOGOUT',
        request=request,
        user=user,
        success=True,
        description=f"User logged out: {username}"
    )
    
    logout(request)
    logger.info(f"User logged out: {username}")
    return JsonResponse({'ok': True, 'message': 'Logged out successfully'})
