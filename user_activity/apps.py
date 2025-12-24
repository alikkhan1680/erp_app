# user_activity/apps.py
from django.apps import AppConfig

class UserActivityConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'user_activity'

    def ready(self):
        import user_activity.signals
