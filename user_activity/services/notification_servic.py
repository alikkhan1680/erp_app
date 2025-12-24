from ..models import Notification

def create_notification(user, message):
    """
    Foydalanuvchiga Notification qo'shadi
    """
    Notification.objects.create(
        user=user,
        message=message
    )

def mark_notification_read(notification):
    """
    Notification ni o'qilgan qilib belgilaydi
    """
    notification.read = True
    notification.save()
