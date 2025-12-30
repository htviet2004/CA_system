from django.db import models
from django.contrib.auth.models import User


class UserCert(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    common_name = models.CharField(max_length=200, blank=True)
    p12_enc_path = models.CharField(max_length=1024)
    p12_pass_enc_path = models.CharField(max_length=1024)
    created_at = models.DateTimeField(auto_now_add=True)
    active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.user.username} - {self.common_name or 'cert'}"
