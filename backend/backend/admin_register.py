from django.contrib import admin
from django.apps import apps

# Register all models from all installed apps so they appear in Django admin.
# Skip models that are already registered.
for model in apps.get_models():
    try:
        admin.site.register(model)
    except admin.sites.AlreadyRegistered:
        pass
