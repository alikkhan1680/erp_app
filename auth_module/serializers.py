from django.core.exceptions import ValidationError
from rest_framework import serializers
from django.core.validators import RegexValidator
from accounts.models import CustomUser
from accounts.utils import validate_password
from .utilits import verify_turnstile
import secrets


class RegisterOwnerSerializer(serializers.Serializer):
    full_name = serializers.CharField(max_length=255, allow_blank=False, help_text="Foydalanuvchi to'liq ismi")
    primary_mobile = serializers.CharField(
        max_length=15,
        allow_blank=False,
        help_text="+998901234567 formatida bo'lishi kerak"
    )
    password = serializers.CharField(
        write_only=True,
        min_length=8,
        max_length=40,
        help_text="Kamida 1 katta harf, 1 kichik harf, 1 raqam, 1 maxsus belgi"
    )

    # 🔹 passwordni validate qilish
    def validate_password(self, value):
        try:
            validate_password(value)  # Siz yozgan funksiya chaqiriladi
        except ValidationError as e:
            raise serializers.ValidationError(e)
        return value


class SignupSerializer(serializers.Serializer):
    full_name = serializers.CharField(max_length=255, allow_blank=False)
    primary_mobile = serializers.CharField(
        max_length=20,
        validators=[
            RegexValidator(
                regex=r'^\+\d{9,15}$',
                message="telefon raqam + country formatida bo'lishii kerak"
            )
        ]
    )


class OTPVerifyserializers(serializers.Serializer):
    primary_mobile = serializers.CharField(max_length=20)
    otp_code = serializers.CharField(max_length=6)

    def validate(self, data):
        phone = data.get('primary_mobile')
        otp = data.get('otp_code')

        if not phone or not otp:
            raise serializers.ValidationError("primary_mobile va otp_code majburiy")
        return data


class ResentOTPSerializers(serializers.Serializer):
    primary_mobile = serializers.CharField(
        validators=[
            RegexValidator(
                regex=r'^\+\d{9,15}$',
                message="telefon raqam + country formatida bo'lishi kerak "
            )
        ]
    )


# serializers.py
class LoginSerializer(serializers.Serializer):
    username_or_phone = serializers.CharField()
    password = serializers.CharField(write_only=True)
    remember_me = serializers.BooleanField(default=False)
    cf_turnstile_response = serializers.CharField(
        write_only=True,
        required=False,
        help_text="Cloudflare Turnstile token"
    )

    def validate(self, attrs):
        username_or_phone = attrs.get('username_or_phone')
        password = attrs.get('password')
        remember_me = attrs.get('remember_me')
        token = attrs.get('cf_turnstile_response')

        # 🔹 Step 1: Turnstile tekshiruvi
        from django.conf import settings
        if not getattr(settings, "TEST_MODE", False):
            if not token or not verify_turnstile(token):
                raise serializers.ValidationError("Invalid Turnstile token")

        # 🔹 Step 2: User topish (username, primary_mobile, email)
        user = None
        try:
            user = CustomUser.objects.get(username=username_or_phone)
        except CustomUser.DoesNotExist:
            try:
                user = CustomUser.objects.get(primary_mobile=username_or_phone)
            except CustomUser.DoesNotExist:
                try:
                    user = CustomUser.objects.get(email=username_or_phone)
                except CustomUser.DoesNotExist:
                    raise serializers.ValidationError("Username/Phone/Email yoki parol noto'g'ri")

        # 🔹 Step 3: Password tekshirish
        if user.check_password(password):
            attrs['user'] = user
            attrs['remember_me'] = remember_me
            return attrs

        raise serializers.ValidationError("Username/Phone/Email yoki parol noto'g'ri")



class RefreshTokenSerializers(serializers.Serializer):
    refresh = serializers.CharField(
        write_only=True,
        required=True,
        help_text="yaroqli refresh token"
    )



class Enable2FASerializer(serializers.Serializer):
    class Meta:
        model = CustomUser
        fields = ('is_2fa_enabled', 'two_fa_secret', 'backup_codes')

    def update(self, instance, validated_data):
        instance.is_2fa_enabled = True #2fani yoqamiz

        import pyotp
        instance.two_fa_secret = pyotp.random_base32() # secret codlar yaratish uchn ishlatamiz

        recovery_codes = [secrets.token_hex(4) for _ in range(5)]
        instance.backup_codes = recovery_codes

        instance.save()
        return instance


class TwoFABackupVerifySerializer(serializers.Serializer):
    session_id = serializers.UUIDField()
    backup_code = serializers.CharField(max_length=100)



class TwoFACodeVerifySerializer(serializers.Serializer):
    session_id = serializers.UUIDField()
    code = serializers.CharField(max_length=10)












