from datetime import timedelta
from uuid import uuid4

from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from .manager import UserManager
import uuid



class CustomUser(AbstractUser):
    full_name = models.CharField(max_length=255)
    primary_mobile = models.CharField(max_length=15, unique=True)

    user_role = models.CharField(
        max_length=20,
        choices=[
            ('account_owner', 'Account Owner'),
            ('admin', 'Admin'),
            ('manager', 'Manager'),
            ('employee', 'Employee'),
        ],
        default='employee'
    )
    objects = UserManager()

    email_verified = models.BooleanField(default=False)
    phone_verified = models.BooleanField(default=False)
    user_id_number = models.CharField(max_length=20,unique=True,blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


    is_2fa_enabled = models.BooleanField(default=False)
    two_fa_secret = models.CharField(max_length=255, null=True, blank=True)
    two_fa_type = models.CharField(max_length=20,choices=(('AUTHENTICATOR', 'Authenticator'), ('SMS', 'SMS')),default='AUTHENTICATOR')
    backup_codes = models.JSONField(default=list, blank=True)

    # optional: so‘nggi muvaffaqiyatli 2FA tekshiruvi
    last_2fa_verified_at = models.DateTimeField(null=True, blank=True)
    failed_login_attempts = models.PositiveIntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)

    def is_locked(self):
        return self.locked_until and self.locked_until > timezone.now()

    def lock_account(self, minutes=30):
        self.locked_until = timezone.now() + timedelta(minutes=minutes)
        self.save(update_fields=["locked_until"])

    def reset_failed_attempts(self):
        self.failed_login_attempts = 0
        self.locked_until = None
        self.save(update_fields=["failed_login_attempts", "locked_until"])

    def __str__(self):
        return self.username

    def save(self, *args, **kwargs):
        if not self.user_id_number:
            self.user_id_number = f"USR-{uuid.uuid4().hex[:12].upper()}"
        super().save(*args, **kwargs)

    def __str__(self):
        return self.username


class TwoALoginSession(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    session_id = models.UUIDField(default=uuid4, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_verified = models.BooleanField(default=False)

    def is_expired(self):
        return timezone.now() > self.created_at +timedelta(minutes=5)

    def __str__(self):
        return f"{self.user} - {self.session_id}"





class RoleChangeLog(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='role_changes')
    old_role = models.CharField(max_length=20)
    new_role = models.CharField(max_length=20)
    changed_by = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, related_name='changed_roles')
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username}: {self.old_role} {self.new_role}"