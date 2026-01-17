import re
from django.core.exceptions import ValidationError
from rest_framework import serializers
from django.core.validators import RegexValidator
from accounts.models import CustomUser
from accounts.utils import validate_password
from .utilits import verify_turnstile

class BaseUserInputSerializer(serializers.Serializer):
    full_name = serializers.CharField(
        min_length=3,
        max_length=255,
        allow_blank=False
    )

    primary_mobile = serializers.CharField(
        max_length=13,
        allow_blank=False,
        validators=[
            RegexValidator(
                regex=r'^\+20(10|11|12|15)\d{8}$',
                message="Phone number must be in the format +201XXXXXXXX (Egypt)"
            )
        ]
    )

    def validate_full_name(self, value):
        if not re.match(r'^[A-Za-z\s]+$', value):
            raise serializers.ValidationError(
                "The name must contain only letters and spaces."
            )
        return value


class RegisterOwnerSerializer(BaseUserInputSerializer):
    password = serializers.CharField(
        write_only=True,
        min_length=8,
        max_length=40,
        help_text="At least 1 uppercase letter, 1 lowercase letter, 1 number, 1 special character"
    )

    # 🔹 passwordni validate qilish
    def validate_password(self, value):
        try:
            validate_password(value)
        except ValidationError as e:
            raise serializers.ValidationError(e.messages)
        return value



class SignupSerializer(BaseUserInputSerializer):
    pass




class OTPVerifyserializers(serializers.Serializer):
    primary_mobile = serializers.CharField(
        max_length=13,
        allow_blank=False,
        validators=[
            RegexValidator(
                regex=r'^\+20(10|11|12|15)\d{8}$',
                message="Phone number must be in the format +201XXXXXXXX (Egypt)"
            )
        ]
    )

    otp_code = serializers.CharField(
        min_length=6,
        max_length=6,
        allow_blank=False,
        validators=[
            RegexValidator(
                regex=r'^\d{6}$',
                message="OTP code must be exactly 6 digits"
            )
        ]
    )




class ResentOTPSerializers(serializers.Serializer):
    primary_mobile = serializers.CharField(
        validators=[
            RegexValidator(
                regex=r'^\+20(10|11|12|15)\d{8}$',
                message="Phone number must be in the format +201XXXXXXXX (Egypt) "
            )
        ]
    )


# serializers.py
class LoginSerializer(serializers.Serializer):
    username_or_phone = serializers.CharField(
        allow_blank=False,
        max_length=255,
        help_text="Username, phone number, or email"
    )

    password = serializers.CharField(
        write_only=True,
        allow_blank=False,
        min_length=8,
        max_length=128
    )

    remember_me = serializers.BooleanField(default=False)

    cf_turnstile_response = serializers.CharField(
        write_only=True,
        required=False,
        allow_blank=False,
        help_text="Cloudflare Turnstile token"
    )

    def get_user_if_exists(self):
        username_or_phone = self.initial_data.get("username_or_phone")
        if not username_or_phone:
            return None

        if username_or_phone.startswith("+"):
            return CustomUser.objects.filter(primary_mobile=username_or_phone).first()
        elif "@" in username_or_phone:
            return CustomUser.objects.filter(email=username_or_phone).first()
        else:
            return CustomUser.objects.filter(username=username_or_phone).first()

    def validate_username_or_phone(self, value):
        """
        Bu yerda faqat FORMATNI tekshiramiz.
        User mavjudligini tekshirmaymiz (security sabab).
        """
        # phone
        if value.startswith("+"):
            if not re.match(r'^\+20(10|11|12|15)\d{8}$', value):
                raise serializers.ValidationError(
                    "Phone number must be in the format +201XXXXXXXX (Egypt)"
                )
        # email
        elif "@" in value:
            serializers.EmailField().run_validation(value)
        # username
        else:
            if len(value) < 3:
                raise serializers.ValidationError(
                    "Username is too short"
                )
        return value

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

        # 🔹 Step 2: User topish
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
                    raise serializers.ValidationError(
                        "Username/Phone/Email or password is incorrect"
                    )

        # 🔹 Step 3: Password tekshirish
        if not user.check_password(password):
            raise serializers.ValidationError(
                "Username/Phone/Email or password is incorrect"
            )

        attrs['user'] = user
        attrs['remember_me'] = remember_me
        return attrs



class RefreshTokenSerializers(serializers.Serializer):
    refresh = serializers.CharField(
        write_only=True,
        allow_blank=False,
        min_length=20,
        max_length=512,
        help_text="Valid refresh token"
    )



class Enable2FASerializer(serializers.Serializer):
    """
    No input fields required.
    Used only to enable 2FA for the current user.
    """

    def save(self, **kwargs):
        user = self.context["request"].user

        import pyotp, secrets

        user.is_2fa_enabled = True
        user.two_fa_secret = pyotp.random_base32()
        user.backup_codes = [secrets.token_hex(4) for _ in range(5)]

        user.save(update_fields=[
            "is_2fa_enabled",
            "two_fa_secret",
            "backup_codes"
        ])
        return user



class TwoFABackupVerifySerializer(serializers.Serializer):
    session_id = serializers.UUIDField()
    backup_code = serializers.CharField(max_length=100)



class TwoFACodeVerifySerializer(serializers.Serializer):
    session_id = serializers.UUIDField()
    code = serializers.CharField(max_length=10)












