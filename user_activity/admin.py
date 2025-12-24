# user_activity/admin.py
from django.contrib import admin
from .models import ActivityLog, Notification
from accounts.models import RoleChangeLog

@admin.register(ActivityLog)
class ActivityLogAdmin(admin.ModelAdmin):
    list_display = ('user', 'action_type', 'description', 'ip_address', 'device', 'created_at')
    list_filter = ('action_type', 'created_at')
    search_fields = ('user__username', 'description', 'ip_address')

@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ('user', 'message', 'read', 'created_at')
    list_filter = ('read', 'created_at')
    search_fields = ('user__username', 'message')

@admin.register(RoleChangeLog)
class RoleChangeLogAdmin(admin.ModelAdmin):
    list_display = ('user', 'old_role', 'new_role', 'changed_by', 'timestamp')
    list_filter = ('old_role', 'new_role', 'timestamp')
    search_fields = ('user__username', 'changed_by__username')
