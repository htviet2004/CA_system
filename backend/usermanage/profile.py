from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from usermanage.models import UserProfile
import json


@csrf_exempt
def update_profile(request):
	"""Create or update a UserProfile for a given username.

	Expects JSON body with at least `username`. Other optional fields:
	`full_name`, `phone`, `department`, `email`, `role`.

	For new users or missing keys, fields will be left empty strings.
	Returns JSON with `ok` and the saved profile fields.
	"""
	if request.method != 'POST':
		return JsonResponse({'error': 'POST only'}, status=405)

	try:
		data = json.loads(request.body.decode('utf-8') or '{}')
	except Exception:
		return JsonResponse({'error': 'invalid json'}, status=400)

	username = data.get('username')
	if not username:
		return JsonResponse({'error': 'username required'}, status=400)

	# find or create user
	user, _created = User.objects.get_or_create(username=username)

	# find or create profile
	profile, _ = UserProfile.objects.get_or_create(user=user)

	# Map allowed fields; for any missing value set to '' (empty string)
	allowed = ['full_name', 'phone', 'department', 'email', 'role']
	for key in allowed:
		if key in data and data[key] is not None:
			setattr(profile, key, data[key])
		else:
			# For new users we leave existing values alone; if you want
			# missing keys to clear values, uncomment the next line.
			# setattr(profile, key, '')
			pass

	# If frontend provided a `full_name` consider syncing to User.first_name
	if 'full_name' in data and data.get('full_name') is not None:
		user.first_name = data.get('full_name')
		user.save()

	profile.save()

	resp = {
		'ok': True,
		'username': username,
		'profile': {
			'full_name': profile.full_name or '',
			'phone': profile.phone or '',
			'department': profile.department or '',
			'email': profile.email or '',
			'role': profile.role or '',
		}
	}
	return JsonResponse(resp)


def get_profile(request, username):
	"""Return existing profile fields for `username` or empty strings.

	Access control: only the user themself or staff can fetch the profile.
	"""
	if request.method != 'GET':
		return JsonResponse({'error': 'GET only'}, status=405)

	if not request.user.is_authenticated:
		return JsonResponse({'error': 'authentication required'}, status=403)

	if not (request.user.is_staff or request.user.username == username):
		return JsonResponse({'error': 'forbidden'}, status=403)

	try:
		user = User.objects.get(username=username)
	except User.DoesNotExist:
		# No user -> return empty profile fields
		return JsonResponse({'ok': True, 'username': username, 'profile': {
			'full_name': '', 'phone': '', 'department': '', 'email': '', 'role': ''
		}})

	profile = None
	try:
		profile = UserProfile.objects.filter(user=user).first()
	except Exception:
		profile = None

	if not profile:
		return JsonResponse({'ok': True, 'username': username, 'profile': {
			'full_name': user.first_name or '',
			'phone': '', 'department': '', 'email': user.email or '', 'role': ''
		}})

	return JsonResponse({'ok': True, 'username': username, 'profile': {
		'full_name': profile.full_name or '',
		'phone': profile.phone or '',
		'department': profile.department or '',
		'email': profile.email or '',
		'role': profile.role or '',
	}})

