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
