"""
Admin API endpoints for full CRUD operations.

SECURITY: All endpoints require staff authentication.
Provides comprehensive admin functionality for:
- Users management (CRUD)
- User profiles management
- Certificates overview
- Signing history management
"""

import json
import logging
from datetime import timedelta

from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Q, Count
from django.utils import timezone
from django.db import transaction

from .models import UserProfile
from signing.validators import validate_username

logger = logging.getLogger(__name__)


def admin_required(view_func):
    """Decorator to require admin (staff) access."""
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'Authentication required'}, status=401)
        if not request.user.is_staff:
            return JsonResponse({'error': 'Admin access required'}, status=403)
        return view_func(request, *args, **kwargs)
    return wrapper


# =============================================================================
# ADMIN DASHBOARD STATS
# =============================================================================

@login_required
@admin_required
def admin_dashboard_stats(request):
    """
    Get admin dashboard statistics.
    """
    from usercerts.models import UserCert, SigningHistory
    
    now = timezone.now()
    start_of_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    last_30_days = now - timedelta(days=30)
    
    # User stats
    total_users = User.objects.count()
    active_users = User.objects.filter(is_active=True).count()
    admin_users = User.objects.filter(is_staff=True).count()
    new_users_month = User.objects.filter(date_joined__gte=start_of_month).count()
    
    # Certificate stats
    total_certs = UserCert.objects.count()
    active_certs = UserCert.objects.filter(active=True).count()
    revoked_certs = UserCert.objects.filter(active=False).count()
    expiring_soon = UserCert.objects.filter(
        active=True,
        expires_at__lte=now + timedelta(days=30),
        expires_at__gt=now
    ).count()
    
    # Signing stats
    total_signatures = SigningHistory.objects.count()
    signatures_this_month = SigningHistory.objects.filter(signed_at__gte=start_of_month).count()
    valid_signatures = SigningHistory.objects.filter(status='valid').count()
    
    # Recent activity
    recent_users = User.objects.order_by('-date_joined')[:5]
    recent_signatures = SigningHistory.objects.select_related('user').order_by('-signed_at')[:5]
    
    return JsonResponse({
        'users': {
            'total': total_users,
            'active': active_users,
            'admins': admin_users,
            'new_this_month': new_users_month,
        },
        'certificates': {
            'total': total_certs,
            'active': active_certs,
            'revoked': revoked_certs,
            'expiring_soon': expiring_soon,
        },
        'signatures': {
            'total': total_signatures,
            'this_month': signatures_this_month,
            'valid': valid_signatures,
        },
        'recent_users': [
            {
                'username': u.username,
                'date_joined': u.date_joined.isoformat(),
                'is_active': u.is_active,
            }
            for u in recent_users
        ],
        'recent_signatures': [
            {
                'id': s.id,
                'username': s.user.username,
                'document_name': s.document_name,
                'signed_at': s.signed_at.isoformat(),
                'status': s.status,
            }
            for s in recent_signatures
        ],
    })


# =============================================================================
# USER MANAGEMENT CRUD
# =============================================================================

@login_required
@admin_required
def admin_list_users(request):
    """
    List all users with pagination, search, and filtering.
    
    Query params:
        - page: Page number (default 1)
        - per_page: Items per page (default 20, max 100)
        - search: Search in username, email, full_name
        - is_active: Filter by active status (true/false)
        - is_staff: Filter by staff status (true/false)
        - role: Filter by role
        - department: Filter by department
        - sort: Sort field (username, date_joined, -username, -date_joined)
    """
    page = int(request.GET.get('page', 1))
    per_page = min(int(request.GET.get('per_page', 20)), 100)
    search = request.GET.get('search', '').strip()
    is_active = request.GET.get('is_active')
    is_staff = request.GET.get('is_staff')
    role = request.GET.get('role')
    department = request.GET.get('department')
    sort = request.GET.get('sort', '-date_joined')
    
    # Base queryset with related profile
    qs = User.objects.select_related('profile').prefetch_related('certificates')
    
    # Search filter
    if search:
        qs = qs.filter(
            Q(username__icontains=search) |
            Q(email__icontains=search) |
            Q(profile__full_name__icontains=search)
        )
    
    # Status filters
    if is_active is not None:
        qs = qs.filter(is_active=(is_active.lower() == 'true'))
    if is_staff is not None:
        qs = qs.filter(is_staff=(is_staff.lower() == 'true'))
    
    # Profile filters
    if role:
        qs = qs.filter(profile__role=role)
    if department:
        qs = qs.filter(profile__department=department)
    
    # Sorting
    valid_sorts = ['username', '-username', 'date_joined', '-date_joined', 'email', '-email']
    if sort in valid_sorts:
        qs = qs.order_by(sort)
    else:
        qs = qs.order_by('-date_joined')
    
    # Pagination
    paginator = Paginator(qs, per_page)
    page_obj = paginator.get_page(page)
    
    users = []
    for u in page_obj:
        profile = getattr(u, 'profile', None)
        cert_count = u.certificates.filter(active=True).count()
        
        users.append({
            'id': u.id,
            'username': u.username,
            'email': u.email,
            'is_active': u.is_active,
            'is_staff': u.is_staff,
            'date_joined': u.date_joined.isoformat(),
            'last_login': u.last_login.isoformat() if u.last_login else None,
            'profile': {
                'full_name': profile.full_name if profile else '',
                'phone': profile.phone if profile else '',
                'role': profile.role if profile else 'student',
                'role_display': profile.get_role_display() if profile else 'Student',
                'department': profile.department if profile else '',
                'department_display': profile.get_department_display() if profile and profile.department else '',
                'created_at': profile.created_at.isoformat() if profile else None,
                'updated_at': profile.updated_at.isoformat() if profile else None,
            } if profile else None,
            'active_certificates': cert_count,
        })
    
    return JsonResponse({
        'users': users,
        'pagination': {
            'total': paginator.count,
            'page': page,
            'per_page': per_page,
            'total_pages': paginator.num_pages,
            'has_next': page_obj.has_next(),
            'has_prev': page_obj.has_previous(),
        }
    })


@login_required
@admin_required
def admin_get_user(request, user_id):
    """
    Get detailed user information by ID.
    """
    from usercerts.models import UserCert, SigningHistory
    
    try:
        user = User.objects.select_related('profile').get(id=user_id)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)
    
    profile = getattr(user, 'profile', None)
    
    # Get certificates
    certs = UserCert.objects.filter(user=user).order_by('-created_at')
    
    # Get signing stats
    signing_count = SigningHistory.objects.filter(user=user).count()
    
    return JsonResponse({
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'is_active': user.is_active,
            'is_staff': user.is_staff,
            'is_superuser': user.is_superuser,
            'date_joined': user.date_joined.isoformat(),
            'last_login': user.last_login.isoformat() if user.last_login else None,
        },
        'profile': {
            'full_name': profile.full_name if profile else '',
            'email': profile.email if profile else '',
            'phone': profile.phone if profile else '',
            'role': profile.role if profile else 'student',
            'role_display': profile.get_role_display() if profile else 'Student',
            'department': profile.department if profile else '',
            'department_display': profile.get_department_display() if profile and profile.department else '',
            'notes': profile.notes if profile else '',
            'created_at': profile.created_at.isoformat() if profile else None,
            'updated_at': profile.updated_at.isoformat() if profile else None,
        } if profile else None,
        'certificates': [
            {
                'id': c.id,
                'common_name': c.common_name,
                'serial_number': c.serial_number,
                'active': c.active,
                'created_at': c.created_at.isoformat(),
                'expires_at': c.expires_at.isoformat() if c.expires_at else None,
                'revoked_at': c.revoked_at.isoformat() if c.revoked_at else None,
                'revocation_reason': c.revocation_reason,
            }
            for c in certs
        ],
        'signing_count': signing_count,
    })


@login_required
@admin_required
@require_http_methods(["POST"])
def admin_create_user(request):
    """
    Create a new user with profile.
    
    POST body (JSON):
        - username: Required
        - password: Required
        - email: Optional
        - is_active: Optional (default True)
        - is_staff: Optional (default False)
        - profile: Optional object with full_name, phone, role, department, notes
    """
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    
    username = data.get('username', '').strip()
    password = data.get('password', '')
    email = data.get('email', '').strip()
    is_active = data.get('is_active', True)
    is_staff = data.get('is_staff', False)
    profile_data = data.get('profile', {})
    
    # Validation
    if not username:
        return JsonResponse({'error': 'Username is required'}, status=400)
    
    try:
        username = validate_username(username)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)
    
    if not password or len(password) < 8:
        return JsonResponse({'error': 'Password must be at least 8 characters'}, status=400)
    
    if User.objects.filter(username=username).exists():
        return JsonResponse({'error': 'Username already exists'}, status=400)
    
    if email and User.objects.filter(email=email).exists():
        return JsonResponse({'error': 'Email already exists'}, status=400)
    
    try:
        with transaction.atomic():
            # Create user
            user = User.objects.create_user(
                username=username,
                password=password,
                email=email,
                is_active=is_active,
                is_staff=is_staff,
            )
            
            # Create or update profile
            profile, created = UserProfile.objects.get_or_create(user=user)
            profile.full_name = profile_data.get('full_name', '')
            profile.phone = profile_data.get('phone', '')
            profile.role = profile_data.get('role', 'student')
            profile.department = profile_data.get('department', '')
            profile.notes = profile_data.get('notes', '')
            if email:
                profile.email = email
            profile.save()
            
            logger.info(f"Admin {request.user.username} created user: {username}")
            
            return JsonResponse({
                'ok': True,
                'user_id': user.id,
                'username': user.username,
                'message': 'User created successfully',
            }, status=201)
            
    except Exception as e:
        logger.error(f"Failed to create user: {e}")
        return JsonResponse({'error': 'Failed to create user'}, status=500)


@login_required
@admin_required
@require_http_methods(["PUT", "PATCH"])
def admin_update_user(request, user_id):
    """
    Update user information.
    
    PUT/PATCH body (JSON):
        - email: Optional
        - is_active: Optional
        - is_staff: Optional
        - profile: Optional object with full_name, phone, role, department, notes
    """
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)
    
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    
    # Prevent self-demotion
    if user == request.user and 'is_staff' in data and not data['is_staff']:
        return JsonResponse({'error': 'Cannot remove your own admin privileges'}, status=400)
    
    try:
        with transaction.atomic():
            # Update user fields
            if 'email' in data:
                email = data['email'].strip()
                if email and email != user.email:
                    if User.objects.filter(email=email).exclude(id=user_id).exists():
                        return JsonResponse({'error': 'Email already exists'}, status=400)
                    user.email = email
            
            if 'is_active' in data:
                user.is_active = bool(data['is_active'])
            
            if 'is_staff' in data:
                user.is_staff = bool(data['is_staff'])
            
            user.save()
            
            # Update profile
            if 'profile' in data:
                profile_data = data['profile']
                profile, created = UserProfile.objects.get_or_create(user=user)
                
                if 'full_name' in profile_data:
                    profile.full_name = profile_data['full_name']
                if 'phone' in profile_data:
                    profile.phone = profile_data['phone']
                if 'role' in profile_data:
                    profile.role = profile_data['role']
                if 'department' in profile_data:
                    profile.department = profile_data['department']
                if 'notes' in profile_data:
                    profile.notes = profile_data['notes']
                if 'email' in profile_data:
                    profile.email = profile_data['email']
                
                profile.save()
            
            logger.info(f"Admin {request.user.username} updated user: {user.username}")
            
            return JsonResponse({
                'ok': True,
                'message': 'User updated successfully',
            })
            
    except Exception as e:
        logger.error(f"Failed to update user: {e}")
        return JsonResponse({'error': 'Failed to update user'}, status=500)


@login_required
@admin_required
@require_http_methods(["DELETE"])
def admin_delete_user(request, user_id):
    """
    Delete a user (soft delete by deactivating, or hard delete if no signing history).
    
    Query params:
        - hard: If 'true', permanently delete user (only if no signing history)
    """
    from usercerts.models import SigningHistory
    
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)
    
    # Prevent self-deletion
    if user == request.user:
        return JsonResponse({'error': 'Cannot delete yourself'}, status=400)
    
    hard_delete = request.GET.get('hard', '').lower() == 'true'
    
    # Check for signing history
    has_history = SigningHistory.objects.filter(user=user).exists()
    
    if hard_delete:
        if has_history:
            return JsonResponse({
                'error': 'Cannot hard delete user with signing history. Use soft delete instead.'
            }, status=400)
        
        username = user.username
        user.delete()
        logger.info(f"Admin {request.user.username} hard deleted user: {username}")
        
        return JsonResponse({
            'ok': True,
            'message': f'User {username} permanently deleted',
            'deleted': True,
        })
    else:
        # Soft delete - just deactivate
        user.is_active = False
        user.save()
        logger.info(f"Admin {request.user.username} soft deleted (deactivated) user: {user.username}")
        
        return JsonResponse({
            'ok': True,
            'message': f'User {user.username} deactivated',
            'deleted': False,
            'deactivated': True,
        })


@login_required
@admin_required
@require_http_methods(["POST"])
def admin_reset_user_password(request, user_id):
    """
    Reset a user's password and return temporary password.
    """
    import secrets
    
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)
    
    # Generate secure temporary password
    temp_password = secrets.token_urlsafe(12)
    user.set_password(temp_password)
    user.save()
    
    logger.info(f"Admin {request.user.username} reset password for user: {user.username}")
    
    return JsonResponse({
        'ok': True,
        'username': user.username,
        'temp_password': temp_password,
        'message': 'Password reset successfully. User should change password on next login.',
    })


# =============================================================================
# CERTIFICATE MANAGEMENT
# =============================================================================

@login_required
@admin_required
def admin_list_certificates(request):
    """
    List all certificates with pagination and filtering.
    """
    from usercerts.models import UserCert
    
    page = int(request.GET.get('page', 1))
    per_page = min(int(request.GET.get('per_page', 20)), 100)
    search = request.GET.get('search', '').strip()
    status = request.GET.get('status')  # active, revoked, expired, expiring
    user_id = request.GET.get('user_id')
    
    qs = UserCert.objects.select_related('user', 'revoked_by').order_by('-created_at')
    
    if search:
        qs = qs.filter(
            Q(user__username__icontains=search) |
            Q(common_name__icontains=search) |
            Q(serial_number__icontains=search)
        )
    
    if user_id:
        qs = qs.filter(user_id=user_id)
    
    now = timezone.now()
    if status == 'active':
        qs = qs.filter(active=True, expires_at__gt=now)
    elif status == 'revoked':
        qs = qs.filter(active=False)
    elif status == 'expired':
        qs = qs.filter(expires_at__lte=now)
    elif status == 'expiring':
        qs = qs.filter(active=True, expires_at__lte=now + timedelta(days=30), expires_at__gt=now)
    
    paginator = Paginator(qs, per_page)
    page_obj = paginator.get_page(page)
    
    certs = []
    for c in page_obj:
        # Determine status
        if not c.active:
            cert_status = 'revoked'
        elif c.expires_at and c.expires_at <= now:
            cert_status = 'expired'
        elif c.expires_at and c.expires_at <= now + timedelta(days=30):
            cert_status = 'expiring'
        else:
            cert_status = 'active'
        
        certs.append({
            'id': c.id,
            'username': c.user.username,
            'user_id': c.user.id,
            'common_name': c.common_name,
            'serial_number': c.serial_number,
            'status': cert_status,
            'active': c.active,
            'created_at': c.created_at.isoformat(),
            'expires_at': c.expires_at.isoformat() if c.expires_at else None,
            'revoked_at': c.revoked_at.isoformat() if c.revoked_at else None,
            'revocation_reason': c.revocation_reason,
            'revoked_by': c.revoked_by.username if c.revoked_by else None,
        })
    
    return JsonResponse({
        'certificates': certs,
        'pagination': {
            'total': paginator.count,
            'page': page,
            'per_page': per_page,
            'total_pages': paginator.num_pages,
        }
    })


# =============================================================================
# SIGNING HISTORY MANAGEMENT
# =============================================================================

@login_required
@admin_required
def admin_list_signing_history(request):
    """
    List all signing history with pagination and filtering.
    """
    from usercerts.models import SigningHistory
    
    page = int(request.GET.get('page', 1))
    per_page = min(int(request.GET.get('per_page', 20)), 100)
    search = request.GET.get('search', '').strip()
    status = request.GET.get('status')
    user_id = request.GET.get('user_id')
    date_from = request.GET.get('date_from')
    date_to = request.GET.get('date_to')
    
    qs = SigningHistory.objects.select_related('user', 'certificate').order_by('-signed_at')
    
    if search:
        qs = qs.filter(
            Q(user__username__icontains=search) |
            Q(document_name__icontains=search) |
            Q(document_hash__icontains=search)
        )
    
    if status:
        qs = qs.filter(status=status)
    
    if user_id:
        qs = qs.filter(user_id=user_id)
    
    if date_from:
        qs = qs.filter(signed_at__date__gte=date_from)
    
    if date_to:
        qs = qs.filter(signed_at__date__lte=date_to)
    
    paginator = Paginator(qs, per_page)
    page_obj = paginator.get_page(page)
    
    history = []
    for h in page_obj:
        history.append({
            'id': h.id,
            'username': h.user.username,
            'user_id': h.user.id,
            'document_name': h.document_name,
            'document_hash': h.document_hash,
            'document_size': h.document_size,
            'signed_at': h.signed_at.isoformat(),
            'status': h.status,
            'reason': h.reason,
            'ip_address': h.ip_address,
            'certificate_cn': h.certificate.common_name if h.certificate else None,
            'is_downloadable': h.is_downloadable() if hasattr(h, 'is_downloadable') else False,
            'download_count': h.download_count,
            'expires_at': h.expires_at.isoformat() if h.expires_at else None,
        })
    
    return JsonResponse({
        'history': history,
        'pagination': {
            'total': paginator.count,
            'page': page,
            'per_page': per_page,
            'total_pages': paginator.num_pages,
        }
    })


@login_required
@admin_required
@require_http_methods(["POST"])
def admin_revoke_signature(request, history_id):
    """
    Revoke a signature (mark as invalid).
    """
    from usercerts.models import SigningHistory
    
    try:
        history = SigningHistory.objects.get(id=history_id)
    except SigningHistory.DoesNotExist:
        return JsonResponse({'error': 'Signing history not found'}, status=404)
    
    if history.status != 'valid':
        return JsonResponse({'error': f'Cannot revoke signature with status: {history.status}'}, status=400)
    
    history.status = 'revoked'
    history.save()
    
    logger.info(f"Admin {request.user.username} revoked signature ID: {history_id}")
    
    return JsonResponse({
        'ok': True,
        'message': 'Signature revoked successfully',
    })


@login_required
@admin_required
@require_http_methods(["POST"])
def admin_revoke_certificate(request, cert_id):
    """
    Revoke a certificate.
    """
    from usercerts.models import UserCert
    
    try:
        cert = UserCert.objects.get(id=cert_id)
    except UserCert.DoesNotExist:
        return JsonResponse({'error': 'Certificate not found'}, status=404)
    
    if not cert.active:
        return JsonResponse({'error': 'Certificate is already revoked'}, status=400)
    
    # Parse reason from request body
    try:
        data = json.loads(request.body)
        reason = data.get('reason', 'unspecified')
    except:
        reason = 'unspecified'
    
    # Revoke the certificate
    cert.active = False
    cert.revocation_reason = reason
    cert.revoked_at = timezone.now()
    cert.save()
    
    logger.info(f"Admin {request.user.username} revoked certificate ID: {cert_id}, reason: {reason}")
    
    return JsonResponse({
        'ok': True,
        'message': 'Certificate revoked successfully',
    })


# =============================================================================
# UTILITY ENDPOINTS
# =============================================================================

@login_required
@admin_required
def admin_get_meta(request):
    """
    Get metadata for admin forms (roles, departments, etc.).
    """
    return JsonResponse({
        'roles': UserProfile.get_role_choices_list(),
        'departments': UserProfile.get_department_choices_list(),
        'certificate_revocation_reasons': [
            {'value': code, 'label': label}
            for code, label in __import__('usercerts.models', fromlist=['UserCert']).UserCert.REVOCATION_REASONS
        ],
    })
