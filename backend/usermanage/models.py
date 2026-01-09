from django.db import models
from django.contrib.auth.models import User


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    phone = models.CharField(max_length=32, blank=True)
    department = models.CharField(max_length=128, blank=True)
    full_name = models.CharField(max_length=128, blank=True)
    email = models.EmailField(blank=True)
    role = models.CharField(max_length=32, blank=True)
    
    def __str__(self):
        return f"Profile: {self.user.username}"
