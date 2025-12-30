from functools import partial

import pyotp
from drf_yasg.utils import swagger_auto_schema
from requests import session
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions, serializers, generics
from django.utils import timezone
from datetime import timedelta
import random
from .models import OTP, LoginActivity
from accounts.models import CustomUser, TwoALoginSession
from .serializers import (
    Enable2FASerializer, SignupSerializer, RefreshTokenSerializers,
    OTPVerifyserializers, ResentOTPSerializers, LoginSerializer,
    TwoFACodeVerifySerializer, TwoFABackupVerifySerializer )
from .utilits import verify_turnstile

MAX_ATTEMPTS = 3
BLOCK_MINUTES = 15
OTP_EXPIRY_MINUTES = 5


# SIGNUP VIEW
class SignUPView(APIView):

    @swagger_auto_schema(request_body=SignupSerializer, security=[])
    def post(self, request):
        serializer = SignupSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        phone_number = serializer.validated_data.get('primary_mobile')
        full_name = serializer.validated_data.get('full_name')

        # user yaratish yoki topish
        user, created = CustomUser.objects.get_or_create(
            primary_mobile=phone_number,
            defaults={'full_name': full_name, "username": full_name}
        )

        # eski OTPlarni o‘chirish
        OTP.objects.filter(phone_number=phone_number).delete()

        # yangi OTP yaratish
        otp_code = str(random.randint(100000, 999999))
        expires_at = timezone.now() + timedelta(minutes=5)

        OTP.objects.create(phone_number=phone_number, otp_code=otp_code, expires_at=expires_at)
        print(f"OTP for {phone_number} is {otp_code}")

        return Response(
            {"message": "OTP sent successfully", "expiry": "5 minutes"},
            status=status.HTTP_200_OK
        )



# VERIFY OTP VIEW
class OTPVerifyView(APIView):
    @swagger_auto_schema(request_body=OTPVerifyserializers, security=[])
    def post(self, request):
        serializer = OTPVerifyserializers(data=request.data)
        serializer.is_valid(raise_exception=True)

        phone_number = serializer.validated_data.get('primary_mobile')
        otp_code = serializer.validated_data.get('otp_code')

        otp_entry = OTP.objects.filter(phone_number=phone_number).first()
        if not otp_entry:
            return Response({"error": "OTP not found. Please request a new one."}, status=status.HTTP_400_BAD_REQUEST)

        # bloklanganmi tekshirish
        if otp_entry.is_blocked:
            if otp_entry.blocked_until and otp_entry.blocked_until > timezone.now():
                return Response(
                    {"error": f"Too many failed attempts. Try again after {otp_entry.blocked_until}"},
                    status=status.HTTP_403_FORBIDDEN
                )
            else:
                #block mudati tugagan, attepts reset
                otp_entry.is_blocked = False
                otp_entry.attempts = 0
                otp_entry.blocked_until = None
                otp_entry.save()

        # muddati tugaganmi
        if otp_entry.expires_at < timezone.now():
            otp_entry.delete()
            return Response({"error": "OTP expired, please request a new one"}, status=status.HTTP_400_BAD_REQUEST)



        # OTP tekshirish
        if otp_entry.otp_code != otp_code:
            otp_entry.attempts += 1
            if otp_entry.attempts >= MAX_ATTEMPTS:
                otp_entry.is_blocked = True
                otp_entry.blocked_until = timezone.now() + timedelta(minutes=BLOCK_MINUTES)
            otp_entry.save()
            attempts_left = MAX_ATTEMPTS - otp_entry.attempts
            return Response({"error": f"Incorrect OTP, you have {attempts_left} attempts left"}, status=status.HTTP_400_BAD_REQUEST)

        # to‘g‘ri bo‘lsa
        user = CustomUser.objects.filter(primary_mobile=phone_number).first()
        if user:
            user.phone_verified = True
            user.save()
        else:
            return Response({"error": "User with this number does not exist"}, status=status.HTTP_400_BAD_REQUEST)

        otp_entry.delete()
        return Response({"message": "Mobile number verified successfully"}, status=status.HTTP_200_OK)



class ResentOTPView(APIView):

    @swagger_auto_schema(request_body=ResentOTPSerializers, security=[])
    def post(self, request):
        token = request.data.get("cf-turnstile-response")
        if not token or not verify_turnstile(token, request.META.get('REMOTE_ADDR')):
            return Response({"error": "Human verification faild"}, status=400)

        serializer = ResentOTPSerializers(data=request.data)
        serializer.is_valid(raise_exception=True)

        phone_number = serializer.validated_data["primary_mobile"]

        #oxirgi otpni olish uchun
        otp_entry = OTP.objects.filter(phone_number=phone_number).first()

        if not otp_entry:
            return Response(
                {"error": "OTP request topilmadi , avval sign up qiling"},
                status=status.HTTP_403_FORBIDDEN
            )

        OTP.objects.filter(phone_number=phone_number).delete()

        # yangi otp yaratish uchun
        otp_code = str(random.randint(100000, 999999))
        expires_at = timezone.now() + timedelta(minutes=OTP_EXPIRY_MINUTES)

        OTP.objects.create(
            phone_number=phone_number,
            otp_code=otp_code,
            expires_at=expires_at,
            attempts=0,
            is_blocked=False,
            blocked_until=None
        )

        # DEV uchun konsolda ko'rish uchun
        print(f"resent otp for {phone_number}: {otp_code}")

        return Response(
            {
                "message": "OTP resent succrsfully",
                "expiry": "5 minutes"
            },
            status=status.HTTP_200_OK
        )



# views.py
class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        return Response({
            "username_or_phone": "user@example.com",
            "password": "userpassword",
            "remember_me": True,
            "cf-turnstile-response": "TOKEN_HERE"
        })

    @swagger_auto_schema(request_body=LoginSerializer, security=[])
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data['user']
        remember_me = serializer.validated_data['remember_me']

        # ================================
        # 🔐 2FA YOQILGANMI? Shuni tekshiramiz
        # ================================
        if getattr(user, "is_2fa_enabled", False):
            # ❗ Session yaratish
            session = TwoALoginSession.objects.create(user=user)

            # 🔹 Code generate qilish
            if user.two_fa_type == "AUTHENTICATOR":
                import pyotp
                totp = pyotp.TOTP(user.two_fa_secret)
                generated_code = totp.now()  # dev/testing uchun
            elif user.two_fa_type == "SMS":
                generated_code = str(random.randint(100000, 999999))
                # send_sms(user.primary_mobile, generated_code)  # Production-da

            LoginActivity.objects.create(
                user=user,
                ip_address=self.get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )

            return Response({
                "message": "2FA verification required",
                "2fa_required": True,
                "session_id": str(session.session_id),
                "generated_code": generated_code  # faqat dev/testing
            }, status=status.HTTP_200_OK)

        # ================================
        # 🔓 2FA yoqilmagan → oddiy login ishlaydi
        # ================================
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)

        if remember_me:
            refresh.access_token.set_exp(lifetime=timedelta(days=14))

        LoginActivity.objects.create(
            user=user,
            ip_address=self.get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )

        return Response({
            "access": access_token,
            "refresh": refresh_token,
            "user_role": user.user_role,
            "2fa_required": False
        }, status=status.HTTP_200_OK)

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip





class LogouteView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data['refresh']
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"detail": "logout successful"}, status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class RefreshTokenView(APIView):
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(request_body=RefreshTokenSerializers, security=[])
    def post(self, request):
        serializer = RefreshTokenSerializers(data=request.data)
        serializer.is_valid(raise_exception=True)

        refresh_token = serializer.validated_data['refresh']
        try:
            token = RefreshToken(refresh_token)
            new_access = str(token.access_token)
            return Response({"access": new_access}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)



class Enable2FAView(generics.UpdateAPIView):
    serializer_class = Enable2FASerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user
    @swagger_auto_schema(request_body=Enable2FASerializer, security=[])
    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({
            "message": "2FA enabled successfully",
            "backup_codes": serializer.instance.backup_codes
        })



class TwoFAVerifyBackupView(APIView):
    permission_classes = [permissions.AllowAny]
    def get(self, request):
        return Response({
              "session_id": "uuid-from-login-response",
              "backup_code": "ABC123"
            })

    @swagger_auto_schema(request_body=TwoFABackupVerifySerializer, security=[])
    def post(self, request):
        serializer = TwoFABackupVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        session_id = serializer.validated_data["session_id"]
        backup_code = serializer.validated_data["backup_code"]

        try:
            session = TwoALoginSession.objects.get(session_id=session_id, is_verified=False)
        except TwoALoginSession.DoesNotExist:
            return Response({"error": "Invalid or expired session"}, status=400)

        if session.is_expired():
            return Response({"error": "session expired"}, status=400)

        user = session.user

        if backup_code not in user.backup_codes:
            return  Response({"error": "Invalid backup code"}, status=400)


        user.backup_codes.remove(backup_code)
        user.save()


        refresh = RefreshToken.for_user(user)

        return Response({
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "message": "Login successful via backup code"
        }, status=200)

class TwoFAVerifyCodeView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        return Response({
            "session_id": "uuid-from-login-response",
            "code": "123456"
        })

    @swagger_auto_schema(request_body=TwoFACodeVerifySerializer, security=[])
    def post(self, request):
        serializer = TwoFACodeVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        session_id = serializer.validated_data["session_id"]
        code = serializer.validated_data["code"]

        # 🔹 Sessionni olish
        try:
            session = TwoALoginSession.objects.get(session_id=session_id, is_verified=False)
        except TwoALoginSession.DoesNotExist:
            return Response({"error": "Invalid or expired session"}, status=400)

        if session.is_expired():
            return Response({"error": "Expired session"}, status=400)

        user = session.user

        # 🔹 Code verify qilish
        if user.two_fa_type == "AUTHENTICATOR":
            import pyotp
            totp = pyotp.TOTP(user.two_fa_secret)
            if not totp.verify(code, valid_window=6):
                return Response({"error": "Invalid 2FA code"}, status=400)
        elif user.two_fa_type == "SMS":
            # TODO: SMS code tekshirish logikasi
            return Response({"error": "SMS verification not implemented yet"}, status=400)

        # 🔹 Sessionni tasdiqlash
        session.is_verified = True
        session.save()

        # 🔹 Token yaratish
        refresh = RefreshToken.for_user(user)

        return Response({
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "message": "Login successful"
        }, status=200)

























