from django.db import models
from django.conf import settings

class Notification(models.Model):
    user  = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='notification')
    message = models.TextField()
    read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Notification for  {self.user.username}"




class ActivityLog(models.Model):

    class ActionTypes(models.TextChoices):
        LOGIN_SUCCESS = "LOGIN_SUCCESS", "Login Success"
        LOGOUT = "LOGOUT", "Logout"
        SIGNUP = "SIGNUP", "Signup"
        ROLE_CHANGED = "ROLE_CHANGED", "Role Changed"
        # boshqa kerakli actionlarni qo'shish mumkin

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    action_type = models.CharField(
        max_length=50,
        choices=ActionTypes.choices
    )
    description = models.TextField(blank=True, null=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    device = models.CharField(max_length=255, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user} - {self.action_type} - {self.created_at}"