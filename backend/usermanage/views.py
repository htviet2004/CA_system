from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.conf import settings
import secrets


def _is_staff_req(request):
    if not request.user.is_authenticated or not request.user.is_staff:
        return False
    return True


@csrf_exempt
def list_users(request):
    if not _is_staff_req(request):
        return JsonResponse({'error': 'staff required'}, status=403)
    qs = User.objects.all().order_by('username')
    out = [{'username': u.username, 'is_active': u.is_active, 'is_staff': u.is_staff} for u in qs]
    return JsonResponse({'users': out})


@csrf_exempt
def user_detail(request, username):
    if not _is_staff_req(request):
        return JsonResponse({'error': 'staff required'}, status=403)
    try:
        u = User.objects.get(username=username)
    except User.DoesNotExist:
        return JsonResponse({'error': 'not found'}, status=404)
    return JsonResponse({'username': u.username, 'is_active': u.is_active, 'is_staff': u.is_staff, 'email': u.email})


@csrf_exempt
def set_active(request, username):
    if not _is_staff_req(request):
        return JsonResponse({'error': 'staff required'}, status=403)
    action = request.POST.get('active')
    if action not in ('0', '1'):
        return JsonResponse({'error': 'provide active=0 or 1'}, status=400)
    try:
        u = User.objects.get(username=username)
    except User.DoesNotExist:
        return JsonResponse({'error': 'not found'}, status=404)
    u.is_active = action == '1'
    u.save()
    return JsonResponse({'ok': True, 'username': u.username, 'is_active': u.is_active})


@csrf_exempt
def set_staff(request, username):
    if not _is_staff_req(request):
        return JsonResponse({'error': 'staff required'}, status=403)
    action = request.POST.get('staff')
    if action not in ('0', '1'):
        return JsonResponse({'error': 'provide staff=0 or 1'}, status=400)
    try:
        u = User.objects.get(username=username)
    except User.DoesNotExist:
        return JsonResponse({'error': 'not found'}, status=404)
    u.is_staff = action == '1'
    u.save()
    return JsonResponse({'ok': True, 'username': u.username, 'is_staff': u.is_staff})


@csrf_exempt
def reset_password(request, username):
    if not _is_staff_req(request):
        return JsonResponse({'error': 'staff required'}, status=403)
    try:
        u = User.objects.get(username=username)
    except User.DoesNotExist:
        return JsonResponse({'error': 'not found'}, status=404)
    temp = secrets.token_urlsafe(8)
    u.set_password(temp)
    u.save()
    return JsonResponse({'ok': True, 'username': u.username, 'temp_password': temp})
