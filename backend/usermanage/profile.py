"""
User profile management views.

SECURITY: All endpoints require authentication and use CSRF protection.

PKI CONSIDERATIONS:
- Profile changes do NOT automatically invalidate certificates
- Role/department changes are logged for audit purposes
- Fields affecting certificate subject are clearly documented
"""
import json
import logging
import re

from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from usermanage.models import UserProfile, ProfileChangeLog
from signing.validators import validate_username

logger = logging.getLogger(__name__)


def _get_client_ip(request):
    """Extract client IP from request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')


def _log_profile_change(user, changed_by, field_name, old_value, new_value, ip_address=None):
    """Create audit log entry for profile change."""
    ProfileChangeLog.objects.create(
        user=user,
        changed_by=changed_by,
        field_name=field_name,
        old_value=str(old_value or ''),
        new_value=str(new_value or ''),
        ip_address=ip_address
    )


# SECURITY: Input validation for profile fields
def _validate_profile_field(field_name, value, max_length=200):
    """Validate a profile field value."""
    if value is None:
        return None
    
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    
    value = value.strip()
    if len(value) > max_length:
        raise ValueError(f"{field_name} exceeds maximum length of {max_length}")
    
    # SECURITY: Basic sanitization - no control characters
    if re.search(r'[\x00-\x1f\x7f]', value):
        raise ValueError(f"{field_name} contains invalid characters")
    
    return value


def _validate_email(email):
    """Validate email format."""
    if not email:
        return ''
    
    email = email.strip()
    if len(email) > 254:  # RFC 5321 limit
        raise ValueError("Email too long")
    
    # Basic email pattern validation
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        raise ValueError("Invalid email format")
    
    return email


def _validate_phone(phone):
    """Validate phone number format."""
    if not phone:
        return ''
    
    phone = phone.strip()
    
    # Allow +, digits, spaces, dashes, parentheses
    # E.g., +84 123 456 789, (84) 123-456-789
    cleaned = re.sub(r'[\s\-\(\)]', '', phone)
    
    if not re.match(r'^\+?[0-9]{8,15}$', cleaned):
        raise ValueError("Invalid phone number format. Use format: +84 123 456 789")
    
    return phone


@login_required
@require_http_methods(["POST"])
def update_profile(request):
    """
    Update the authenticated user's profile.
    
    SECURITY: 
    - Requires authentication
    - Validates all input fields
    - Users can only update their own profile (or staff can update any)
    - Only admin can change roles
    - Role/department changes are logged for audit
    
    PKI NOTES:
    - Updating profile does NOT invalidate existing certificates
    - full_name changes may affect FUTURE certificate CN
    - email changes may affect FUTURE certificate SAN
    """
    try:
        data = json.loads(request.body.decode('utf-8') or '{}')
    except (json.JSONDecodeError, UnicodeDecodeError):
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    # SECURITY: Validate username
    username = data.get('username')
    if not username:
        return JsonResponse({'error': 'Username required'}, status=400)
    
    try:
        username = validate_username(username)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)
    
    # SECURITY: Users can only update their own profile unless staff
    is_self = request.user.username == username
    is_admin = request.user.is_staff
    
    if not is_admin and not is_self:
        logger.warning(f"User {request.user.username} attempted to update profile of {username}")
        return JsonResponse({'error': 'Forbidden'}, status=403)

    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)

    profile, created = UserProfile.objects.get_or_create(user=user)
    client_ip = _get_client_ip(request)
    
    changes_made = []
    errors = {}

    # SECURITY: Validate and sanitize all profile fields
    try:
        # Full name - may affect certificate CN
        if 'full_name' in data:
            new_value = _validate_profile_field('full_name', data['full_name'], 100)
            if new_value is not None and new_value != profile.full_name:
                old_value = profile.full_name
                profile.full_name = new_value
                user.first_name = new_value or ''
                changes_made.append(('full_name', old_value, new_value))
        
        # Phone number
        if 'phone' in data:
            try:
                new_value = _validate_phone(data['phone'])
                if new_value != profile.phone:
                    old_value = profile.phone
                    profile.phone = new_value
                    changes_made.append(('phone', old_value, new_value))
            except ValueError as e:
                errors['phone'] = str(e)
        
        # Email - may affect certificate SAN
        if 'email' in data:
            try:
                new_value = _validate_email(data['email'])
                if new_value != profile.email:
                    old_value = profile.email
                    profile.email = new_value
                    changes_made.append(('email', old_value, new_value))
            except ValueError as e:
                errors['email'] = str(e)
        
        # Department - must be from valid choices
        if 'department' in data:
            new_value = data['department'] or ''
            if new_value and not UserProfile.is_valid_department(new_value):
                errors['department'] = 'Invalid department value'
            elif new_value != profile.department:
                old_value = profile.department
                profile.department = new_value
                changes_made.append(('department', old_value, new_value))
        
        # Role - ONLY admin can change roles
        if 'role' in data:
            new_value = data['role'] or ''
            if new_value and not UserProfile.is_valid_role(new_value):
                errors['role'] = 'Invalid role value'
            elif new_value != profile.role:
                if not is_admin:
                    errors['role'] = 'Only administrators can change roles'
                else:
                    old_value = profile.role
                    profile.role = new_value
                    changes_made.append(('role', old_value, new_value))
        
        # Notes
        if 'notes' in data:
            new_value = _validate_profile_field('notes', data['notes'], 500)
            if new_value is not None and new_value != profile.notes:
                old_value = profile.notes
                profile.notes = new_value
                changes_made.append(('notes', old_value, new_value))
        
    except ValueError as e:
        return JsonResponse({'error': str(e)}, status=400)

    # If there are validation errors, return them
    if errors:
        return JsonResponse({'errors': errors}, status=400)

    # Save changes
    if changes_made:
        profile.save()
        user.save()
        
        # Log changes for audit (especially role and department)
        for field_name, old_value, new_value in changes_made:
            _log_profile_change(user, request.user, field_name, old_value, new_value, client_ip)
            
            # Extra logging for sensitive fields
            if field_name in ('role', 'department'):
                logger.info(
                    f"[AUDIT] Profile {field_name} changed for {username}: "
                    f"'{old_value}' -> '{new_value}' by {request.user.username} from {client_ip}"
                )
    
    logger.info(f"Profile updated for user {username} by {request.user.username}")

    return JsonResponse({
        'ok': True,
        'username': username,
        'profile': {
            'full_name': profile.full_name or '',
            'phone': profile.phone or '',
            'department': profile.department or '',
            'email': profile.email or '',
            'role': profile.role or '',
            'notes': profile.notes or '',
        },
        'changes_made': len(changes_made),
        'can_edit_role': is_admin
    })


@login_required
@require_http_methods(["GET"])
def get_profile(request, username):
    """
    Get a user's profile.
    
    SECURITY: Requires authentication. Users can only view their own profile
    unless they have staff privileges.
    
    Returns:
        - Profile data
        - Permission flags (can_edit, can_edit_role)
        - Role/department display labels
    """
    # SECURITY: Validate username
    try:
        username = validate_username(username)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)
    
    is_self = request.user.username == username
    is_admin = request.user.is_staff
    
    # SECURITY: Users can only view their own profile unless staff
    if not is_admin and not is_self:
        logger.warning(f"User {request.user.username} attempted to view profile of {username}")
        return JsonResponse({'error': 'Forbidden'}, status=403)

    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        return JsonResponse({
            'ok': True, 
            'username': username, 
            'profile': {
                'full_name': '', 
                'phone': '', 
                'department': '', 
                'email': '', 
                'role': '',
                'notes': ''
            },
            'can_edit': is_self or is_admin,
            'can_edit_role': is_admin
        })

    profile = UserProfile.objects.filter(user=user).first()

    if not profile:
        return JsonResponse({
            'ok': True, 
            'username': username, 
            'profile': {
                'full_name': user.first_name or '',
                'phone': '', 
                'department': '', 
                'email': user.email or '', 
                'role': '',
                'notes': ''
            },
            'can_edit': is_self or is_admin,
            'can_edit_role': is_admin
        })

    # Get display labels for role and department
    role_display = dict(UserProfile.ROLE_CHOICES).get(profile.role, profile.role)
    dept_display = dict(UserProfile.DEPARTMENT_CHOICES).get(profile.department, profile.department)

    return JsonResponse({
        'ok': True, 
        'username': username, 
        'profile': {
            'full_name': profile.full_name or '',
            'phone': profile.phone or '',
            'department': profile.department or '',
            'department_display': dept_display,
            'email': profile.email or '',
            'role': profile.role or '',
            'role_display': role_display,
            'notes': profile.notes or '',
            'updated_at': profile.updated_at.isoformat() if profile.updated_at else None
        },
        'can_edit': is_self or is_admin,
        'can_edit_role': is_admin
    })

