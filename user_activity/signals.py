from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model

from accounts.models import RoleChangeLog
from user_activity.models import ActivityLog
from user_activity.services.activity_service import log_user_action
from user_activity.services.notification_servic import create_notification

User = get_user_model()

# Helper function
def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

# Login
@receiver(user_logged_in)
def log_login(sender, request, user, **kwargs):
    ip = get_client_ip(request)
    user_agent = request.META.get('HTTP_USER_AGENT', '')
    log_user_action(user=user, action_type=ActivityLog.ActionTypes.LOGIN_SUCCESS, ip_address=ip, device=user_agent)

# Logout
@receiver(user_logged_out)
def log_logout(sender, request, user, **kwargs):
    ip = get_client_ip(request)
    user_agent = request.META.get('HTTP_USER_AGENT', '')
    log_user_action(user=user, action_type=ActivityLog.ActionTypes.LOGOUT, ip_address=ip, device=user_agent)

# Signup
@receiver(post_save, sender=User)
def log_signup(sender, instance, created, **kwargs):
    if created:
        log_user_action(user=instance, action_type=ActivityLog.ActionTypes.SIGNUP)
        create_notification(user=instance, message="Xush kelibsiz! Siz muvaffaqiyatli ro'yxatdan o'tdingiz.")

# Role change
@receiver(post_save, sender=RoleChangeLog)
def notify_role_change(sender, instance, created, **kwargs):
    if created:
        log_user_action(user=instance.user, action_type=ActivityLog.ActionTypes.ROLE_CHANGED,
                        description=f"{instance.old_role} -> {instance.new_role}")
        create_notification(user=instance.user, message=f"Sizning rolingiz {instance.old_role} dan {instance.new_role} ga o'zgardi.")
