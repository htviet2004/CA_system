"""
Meta API endpoints for returning system configuration data.

These endpoints provide frontend with valid options for dropdowns
without hardcoding values in the UI.
"""

from django.http import JsonResponse
from django.views.decorators.http import require_http_methods

from .models import UserProfile


@require_http_methods(["GET"])
def get_roles(request):
    """
    Return list of valid role values.
    
    Public endpoint - no authentication required.
    Used to populate role dropdown in profile form.
    
    Response:
        {
            "roles": [
                {"value": "student", "label": "Student"},
                {"value": "lecturer", "label": "Lecturer"},
                ...
            ]
        }
    """
    roles = UserProfile.get_role_choices_list()
    return JsonResponse({'roles': roles})


@require_http_methods(["GET"])
def get_departments(request):
    """
    Return list of valid department/faculty values.
    
    Public endpoint - no authentication required.
    Used to populate department dropdown in profile form.
    
    Response:
        {
            "departments": [
                {"value": "cntt", "label": "Khoa Công nghệ Thông tin"},
                {"value": "dtvt", "label": "Khoa Điện tử Viễn thông"},
                ...
            ]
        }
    """
    departments = UserProfile.get_department_choices_list()
    return JsonResponse({'departments': departments})


@require_http_methods(["GET"])
def get_all_meta(request):
    """
    Return all meta configuration in a single call.
    
    Useful for initial page load to reduce API calls.
    
    Response:
        {
            "roles": [...],
            "departments": [...]
        }
    """
    return JsonResponse({
        'roles': UserProfile.get_role_choices_list(),
        'departments': UserProfile.get_department_choices_list()
    })
