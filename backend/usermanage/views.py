"""
User management views for administrators.

SECURITY: All endpoints require staff authentication.
"""

import logging

from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.conf import settings

from signing.validators import validate_username

logger = logging.getLogger(__name__)


def _is_staff_req(request):
    """Check if request user is authenticated admin."""
    if not request.user.is_authenticated or not request.user.is_staff:
        return False
    return True


@login_required
def list_users(request):
    """
    List all users (admin only).
    
    SECURITY: Requires staff privileges.
    """
    if not _is_staff_req(request):
        return JsonResponse({'error': 'staff required'}, status=403)
    
    qs = User.objects.all().order_by('username')
    out = [{'username': u.username, 'is_active': u.is_active, 'is_staff': u.is_staff} for u in qs]
    return JsonResponse({'users': out})


@login_required
def user_detail(request, username):
    """
    Get user details (admin only).
    
    SECURITY: Validates username, requires staff privileges.
    """
    if not _is_staff_req(request):
        return JsonResponse({'error': 'staff required'}, status=403)
    
    # SECURITY: Validate username format
    try:
        username = validate_username(username)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)
    
    try:
        u = User.objects.get(username=username)
    except User.DoesNotExist:
        return JsonResponse({'error': 'not found'}, status=404)
    
    return JsonResponse({
        'username': u.username, 
        'is_active': u.is_active, 
        'is_staff': u.is_staff, 
        'email': u.email
    })


@login_required
@require_http_methods(["POST"])
def set_active(request, username):
    """
    Activate or deactivate a user (admin only).
    
    SECURITY: Validates username, requires staff privileges, logs action.
    """
    if not _is_staff_req(request):
        return JsonResponse({'error': 'staff required'}, status=403)
    
    # SECURITY: Validate username format
    try:
        username = validate_username(username)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)
    
    action = request.POST.get('active')
    if action not in ('0', '1'):
        return JsonResponse({'error': 'provide active=0 or 1'}, status=400)
    
    try:
        u = User.objects.get(username=username)
    except User.DoesNotExist:
        return JsonResponse({'error': 'not found'}, status=404)
    
    u.is_active = action == '1'
    u.save()
    
    logger.info(f"User {username} {'activated' if u.is_active else 'deactivated'} by {request.user.username}")
    return JsonResponse({'ok': True, 'username': u.username, 'is_active': u.is_active})


@login_required
@require_http_methods(["POST"])
def set_staff(request, username):
    """
    Grant or revoke staff privileges (admin only).
    
    SECURITY: Validates username, requires staff privileges, logs action.
    """
    if not _is_staff_req(request):
        return JsonResponse({'error': 'staff required'}, status=403)
    
    # SECURITY: Validate username format
    try:
        username = validate_username(username)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)
    
    action = request.POST.get('staff')
    if action not in ('0', '1'):
        return JsonResponse({'error': 'provide staff=0 or 1'}, status=400)
    
    try:
        u = User.objects.get(username=username)
    except User.DoesNotExist:
        return JsonResponse({'error': 'not found'}, status=404)
    
    u.is_staff = action == '1'
    u.save()
    
    logger.info(f"User {username} staff status set to {u.is_staff} by {request.user.username}")
    return JsonResponse({'ok': True, 'username': u.username, 'is_staff': u.is_staff})


@login_required
@require_http_methods(["POST"])
def reset_password(request, username):
    """
    Reset a user's password (admin only).
    
    SECURITY: Validates username, generates secure temporary password, logs action.
    """
    import secrets as py_secrets  # Use Python secrets module
    
    if not _is_staff_req(request):
        return JsonResponse({'error': 'staff required'}, status=403)
    
    # SECURITY: Validate username format
    try:
        username = validate_username(username)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)
    
    try:
        u = User.objects.get(username=username)
    except User.DoesNotExist:
        return JsonResponse({'error': 'not found'}, status=404)
    
    # SECURITY: Generate secure temporary password
    temp = py_secrets.token_urlsafe(12)  # ~72 bits of entropy
    u.set_password(temp)
    u.save()
    
    logger.info(f"Password reset for user {username} by {request.user.username}")
    
    # SECURITY: Note - in production, send via email instead of returning in response
    return JsonResponse({
        'ok': True, 
        'username': u.username, 
        'temp_password': temp,
        'warning': 'User should change password immediately'
    })


# ============================================================================
# USER DASHBOARD APIs
# ============================================================================

@login_required
def get_user_dashboard(request):
    """
    Get combined dashboard data for the current user.
    Returns certificate info and signing stats in one call.
    """
    from usercerts.views import get_certificate_info, get_signing_stats
    from django.http import JsonResponse
    from usercerts.models import UserCert, SigningHistory
    from django.utils import timezone
    from datetime import timedelta
    
    user = request.user
    
    # Get certificate info
    cert = UserCert.objects.filter(user=user, active=True).order_by('-created_at').first()
    
    certificate_data = None
    if cert:
        now = timezone.now()
        expires_at = cert.expires_at
        
        if not cert.active:
            status = 'revoked'
            days_remaining = 0
        elif expires_at and expires_at < now:
            status = 'expired'
            days_remaining = 0
        elif expires_at:
            days_remaining = (expires_at - now).days
            if days_remaining <= 30:
                status = 'warning'
            else:
                status = 'valid'
        else:
            status = 'valid'
            days_remaining = None
        
        certificate_data = {
            'id': cert.id,
            'common_name': cert.common_name,
            'status': status,
            'days_remaining': days_remaining,
            'expires_at': cert.expires_at.isoformat() if cert.expires_at else None,
        }
    
    # Get signing stats
    all_signatures = SigningHistory.objects.filter(user=user)
    total_signed = all_signatures.count()
    valid_signatures = all_signatures.filter(status='valid').count()
    
    start_of_month = timezone.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    this_month = all_signatures.filter(signed_at__gte=start_of_month).count()
    
    signing_stats = {
        'total_signed': total_signed,
        'valid_signatures': valid_signatures,
        'this_month': this_month
    }
    
    return JsonResponse({
        'user': {
            'username': user.username,
            'email': user.email,
            'is_staff': user.is_staff
        },
        'certificate': certificate_data,
        'signing_stats': signing_stats
    })


@login_required
@require_http_methods(["POST"])
def change_password(request):
    """
    Change the current user's password.
    
    SECURITY: Requires current password verification.
    """
    import json
    
    user = request.user
    
    # Parse JSON body
    try:
        if request.content_type == 'application/json':
            data = json.loads(request.body)
        else:
            data = request.POST
        
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    
    if not current_password or not new_password:
        return JsonResponse({'error': 'Both current_password and new_password are required'}, status=400)
    
    # SECURITY: Verify current password
    if not user.check_password(current_password):
        return JsonResponse({'error': 'Current password is incorrect'}, status=401)
    
    # SECURITY: Validate new password strength
    if len(new_password) < 8:
        return JsonResponse({'error': 'New password must be at least 8 characters'}, status=400)
    
    # Change password
    user.set_password(new_password)
    user.save()
    
    # Keep user logged in by updating session
    from django.contrib.auth import update_session_auth_hash
    update_session_auth_hash(request, user)
    
    logger.info(f"Password changed for user: {user.username}")
    
    return JsonResponse({
        'ok': True,
        'message': 'Password changed successfully'
    })


# ============================================================================
# ADMIN DASHBOARD APIs
# ============================================================================

@login_required
def admin_stats(request):
    """
    Get admin dashboard statistics.
    
    SECURITY: Requires staff privileges.
    """
    from usercerts.models import UserCert, SigningHistory
    from django.utils import timezone
    from datetime import timedelta
    
    if not _is_staff_req(request):
        return JsonResponse({'error': 'Admin access required'}, status=403)
    
    now = timezone.now()
    start_of_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    
    # User stats
    total_users = User.objects.count()
    active_users = User.objects.filter(is_active=True).count()
    staff_users = User.objects.filter(is_staff=True).count()
    new_users_this_month = User.objects.filter(date_joined__gte=start_of_month).count()
    
    # Certificate stats
    total_certs = UserCert.objects.count()
    active_certs = UserCert.objects.filter(active=True).count()
    expiring_soon = UserCert.objects.filter(
        active=True, 
        expires_at__isnull=False,
        expires_at__lte=now + timedelta(days=30),
        expires_at__gt=now
    ).count()
    expired_certs = UserCert.objects.filter(
        active=True,
        expires_at__isnull=False,
        expires_at__lt=now
    ).count()
    revoked_certs = UserCert.objects.filter(active=False).count()
    
    # Signing stats
    total_signatures = SigningHistory.objects.count()
    signatures_this_month = SigningHistory.objects.filter(signed_at__gte=start_of_month).count()
    valid_signatures = SigningHistory.objects.filter(status='valid').count()
    revoked_signatures = SigningHistory.objects.filter(status='revoked').count()
    
    # Recent users (last 5)
    recent_users = list(User.objects.order_by('-date_joined')[:5].values(
        'id', 'username', 'date_joined', 'is_active', 'is_staff'
    ))
    for u in recent_users:
        u['date_joined'] = u['date_joined'].isoformat()
    
    # Recent signatures (last 5)
    recent_signatures = []
    for s in SigningHistory.objects.select_related('user').order_by('-signed_at')[:5]:
        recent_signatures.append({
            'id': s.id,
            'username': s.user.username,
            'document_name': s.document_name,
            'status': s.status,
            'signed_at': s.signed_at.isoformat()
        })
    
    return JsonResponse({
        'users': {
            'total': total_users,
            'active': active_users,
            'admins': staff_users,
            'new_this_month': new_users_this_month
        },
        'certificates': {
            'total': total_certs,
            'active': active_certs,
            'expiring_soon': expiring_soon,
            'expired': expired_certs,
            'revoked': revoked_certs
        },
        'signatures': {
            'total': total_signatures,
            'this_month': signatures_this_month,
            'valid': valid_signatures,
            'revoked': revoked_signatures
        },
        'recent_users': recent_users,
        'recent_signatures': recent_signatures
    })


@login_required
def admin_users_list(request):
    """
    List all users with pagination and filtering for admin.
    
    SECURITY: Requires staff privileges.
    """
    from usercerts.models import UserCert, SigningHistory
    from usermanage.models import UserProfile
    
    if not _is_staff_req(request):
        return JsonResponse({'error': 'Admin access required'}, status=403)
    
    # Pagination
    page = int(request.GET.get('page', 1))
    per_page = int(request.GET.get('per_page', 10))
    
    # Filters
    search = request.GET.get('search', '')
    role_filter = request.GET.get('role', '')
    status_filter = request.GET.get('status', '')
    
    qs = User.objects.all()
    
    if search:
        qs = qs.filter(username__icontains=search)
    
    if status_filter == 'active':
        qs = qs.filter(is_active=True)
    elif status_filter == 'inactive':
        qs = qs.filter(is_active=False)
    elif status_filter == 'admin':
        qs = qs.filter(is_staff=True)
    
    total = qs.count()
    qs = qs.order_by('username')[(page - 1) * per_page:page * per_page]
    
    users = []
    for u in qs:
        # Get profile
        profile = UserProfile.objects.filter(user=u).first()
        
        # Get certificate status
        cert = UserCert.objects.filter(user=u, active=True).order_by('-created_at').first()
        cert_status = 'none'
        if cert:
            from django.utils import timezone
            now = timezone.now()
            if cert.expires_at and cert.expires_at < now:
                cert_status = 'expired'
            elif cert.expires_at and (cert.expires_at - now).days <= 30:
                cert_status = 'expiring'
            else:
                cert_status = 'active'
        
        # Get signature count
        signature_count = SigningHistory.objects.filter(user=u).count()
        
        users.append({
            'id': u.id,
            'username': u.username,
            'email': u.email,
            'full_name': profile.full_name if profile else '',
            'department': profile.department if profile else '',
            'role': profile.role if profile else '',
            'is_active': u.is_active,
            'is_staff': u.is_staff,
            'date_joined': u.date_joined.isoformat(),
            'last_login': u.last_login.isoformat() if u.last_login else None,
            'cert_status': cert_status,
            'signature_count': signature_count
        })
    
    return JsonResponse({
        'users': users,
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total,
            'total_pages': (total + per_page - 1) // per_page
        }
    })


@login_required
def admin_user_detail(request, user_id):
    """
    Get detailed user info for admin.
    
    SECURITY: Requires staff privileges.
    """
    from usercerts.models import UserCert, SigningHistory
    from usermanage.models import UserProfile
    
    if not _is_staff_req(request):
        return JsonResponse({'error': 'Admin access required'}, status=403)
    
    try:
        u = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)
    
    profile = UserProfile.objects.filter(user=u).first()
    
    # Get certificates
    certs = UserCert.objects.filter(user=u).order_by('-created_at')
    certificates = [{
        'id': c.id,
        'common_name': c.common_name,
        'serial_number': c.serial_number,
        'active': c.active,
        'created_at': c.created_at.isoformat(),
        'valid_from': c.valid_from.isoformat() if c.valid_from else None,
        'expires_at': c.expires_at.isoformat() if c.expires_at else None,
        'revoked_at': c.revoked_at.isoformat() if c.revoked_at else None,
        'revocation_reason': c.revocation_reason
    } for c in certs]
    
    # Recent signatures
    recent_sigs = SigningHistory.objects.filter(user=u).order_by('-signed_at')[:10]
    signatures = [{
        'id': s.id,
        'document_hash': s.document_hash,
        'filename': s.filename,
        'status': s.status,
        'signed_at': s.signed_at.isoformat()
    } for s in recent_sigs]
    
    return JsonResponse({
        'user': {
            'id': u.id,
            'username': u.username,
            'email': u.email,
            'full_name': profile.full_name if profile else '',
            'phone': profile.phone if profile else '',
            'department': profile.department if profile else '',
            'role': profile.role if profile else '',
            'is_active': u.is_active,
            'is_staff': u.is_staff,
            'date_joined': u.date_joined.isoformat(),
            'last_login': u.last_login.isoformat() if u.last_login else None
        },
        'certificates': certificates,
        'recent_signatures': signatures,
        'total_signatures': SigningHistory.objects.filter(user=u).count()
    })


@login_required
@require_http_methods(["POST"])
def admin_create_user(request):
    """
    Create a new user (admin only).
    
    SECURITY: Requires staff privileges.
    """
    import json
    from usermanage.models import UserProfile
    
    if not _is_staff_req(request):
        return JsonResponse({'error': 'Admin access required'}, status=403)
    
    try:
        data = json.loads(request.body) if request.content_type == 'application/json' else request.POST
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    email = data.get('email', '').strip()
    full_name = data.get('full_name', '').strip()
    department = data.get('department', '').strip()
    role = data.get('role', '').strip()
    is_staff = data.get('is_staff', False)
    
    if not username or not password:
        return JsonResponse({'error': 'Username and password are required'}, status=400)
    
    if User.objects.filter(username=username).exists():
        return JsonResponse({'error': 'Username already exists'}, status=400)
    
    u = User.objects.create_user(username=username, password=password, email=email)
    u.is_staff = bool(is_staff)
    u.save()
    
    # Create profile
    UserProfile.objects.create(
        user=u,
        full_name=full_name,
        department=department,
        role=role
    )
    
    logger.info(f"User {username} created by admin {request.user.username}")
    
    return JsonResponse({
        'ok': True,
        'user_id': u.id,
        'username': u.username
    })


@login_required
@require_http_methods(["POST"])
def admin_update_user(request, user_id):
    """
    Update a user (admin only).
    
    SECURITY: Requires staff privileges.
    """
    import json
    from usermanage.models import UserProfile
    
    if not _is_staff_req(request):
        return JsonResponse({'error': 'Admin access required'}, status=403)
    
    try:
        u = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)
    
    try:
        data = json.loads(request.body) if request.content_type == 'application/json' else request.POST
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    
    # Update User fields
    if 'email' in data:
        u.email = data['email']
    if 'is_active' in data:
        u.is_active = bool(data['is_active'])
    if 'is_staff' in data:
        u.is_staff = bool(data['is_staff'])
    u.save()
    
    # Update profile
    profile, _ = UserProfile.objects.get_or_create(user=u)
    if 'full_name' in data:
        profile.full_name = data['full_name']
    if 'department' in data:
        profile.department = data['department']
    if 'role' in data:
        profile.role = data['role']
    if 'phone' in data:
        profile.phone = data['phone']
    profile.save()
    
    logger.info(f"User {u.username} updated by admin {request.user.username}")
    
    return JsonResponse({'ok': True, 'user_id': u.id})


@login_required
@require_http_methods(["POST"])
def admin_delete_user(request, user_id):
    """
    Delete a user (admin only).
    
    SECURITY: Requires staff privileges. Cannot delete self.
    """
    if not _is_staff_req(request):
        return JsonResponse({'error': 'Admin access required'}, status=403)
    
    try:
        u = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)
    
    if u == request.user:
        return JsonResponse({'error': 'Cannot delete your own account'}, status=400)
    
    username = u.username
    u.delete()
    
    logger.info(f"User {username} deleted by admin {request.user.username}")
    
    return JsonResponse({'ok': True, 'deleted': username})


@login_required
def admin_signing_history(request):
    """
    Get signing history for all users (admin only).
    
    SECURITY: Requires staff privileges.
    """
    from usercerts.models import SigningHistory
    
    if not _is_staff_req(request):
        return JsonResponse({'error': 'Admin access required'}, status=403)
    
    # Pagination
    page = int(request.GET.get('page', 1))
    per_page = int(request.GET.get('per_page', 15))
    
    # Filters
    search = request.GET.get('search', '')
    status_filter = request.GET.get('status', '')
    user_filter = request.GET.get('username', '')
    
    qs = SigningHistory.objects.select_related('user', 'certificate').all()
    
    if search:
        from django.db.models import Q
        qs = qs.filter(
            Q(document_name__icontains=search) | 
            Q(user__username__icontains=search)
        )
    
    if status_filter:
        qs = qs.filter(status=status_filter)
    
    if user_filter:
        qs = qs.filter(user__username__icontains=user_filter)
    
    total = qs.count()
    qs = qs.order_by('-signed_at')[(page - 1) * per_page:page * per_page]
    
    history = [{
        'id': s.id,
        'username': s.user.username,
        'document_name': s.document_name,
        'document_hash': s.document_hash,
        'document_size': s.document_size,
        'status': s.status,
        'signed_at': s.signed_at.isoformat(),
        'reason': s.reason,
        'ip_address': s.ip_address,
        'certificate_cn': s.certificate.common_name if s.certificate else None,
        'certificate_serial': s.certificate.serial_number if s.certificate else None,
        'revoked_at': s.revoked_at.isoformat() if s.revoked_at else None
    } for s in qs]
    
    return JsonResponse({
        'history': history,
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total,
            'total_pages': (total + per_page - 1) // per_page
        }
    })
