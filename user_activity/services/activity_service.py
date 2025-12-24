from ..models import ActivityLog

def log_user_action(user, action_type, ip_address=None, device=None, description=None):
    """
    Foydalanuvchi harakatini ActivityLog ga yozadi
    """
    ActivityLog.objects.create(
        user=user,
        action_type=action_type,
        ip_address=ip_address,
        device=device,
        description=description
    )
