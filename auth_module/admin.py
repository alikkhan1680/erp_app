from django.contrib import admin
from .models import OTP, LoginActivity



@admin.register(OTP)
class OTPAdmin(admin.ModelAdmin):
    list_display = ('phone_number', 'otp_code', 'expires_at', 'attempts', 'is_blocked', 'blocked_until', 'created_at')
    list_filter = ('is_blocked',)
    search_fields = ('phone_number', 'otp_code')
    readonly_fields = ('created_at',)

admin.site.register(LoginActivity)