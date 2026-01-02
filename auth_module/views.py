from spwd import struct_spwd

import pyotp
from drf_yasg.utils import swagger_auto_schema
from requests import session
from rest_framework.permissions import AllowAny
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
from core.messages.error import ERROR_MESSAGES
from core.messages.success import SUCCESS_MESSAGES
from core.messages.warning import WARNING_MESSAGES


MAX_ATTEMPTS = 3
BLOCK_MINUTES = 15
OTP_EXPIRY_MINUTES = 5


# SIGNUP VIEW
class SignUPView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(request_body=SignupSerializer)
    def post(self, request):
        serializer = SignupSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        phone_number = serializer.validated_data.get('primary_mobile')
        full_name = serializer.validated_data.get('full_name')

        if not phone_number or not full_name:
            return Response(
                {"status":"warning", "message":"Missing required fields."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
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
                {
                        "status": "success",
                        "message": SUCCESS_MESSAGES["PHONE_OTP_SENT"],
                        "expiry": "5 minutes"
                      },status=status.HTTP_200_OK
            )
        except Exception as e:
            #System xatolilari uchun
            return Response(
                {"statuse":"error", "message": ERROR_MESSAGES["SYSTEM_ERROR"]},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



# VERIFY OTP VIEW
class OTPVerifyView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(request_body=OTPVerifyserializers)
    def post(self, request):
        serializer = OTPVerifyserializers(data=request.data)
        serializer.is_valid(raise_exception=True)

        phone_number = serializer.validated_data.get('primary_mobile')
        otp_code = serializer.validated_data.get('otp_code')

        if not phone_number or not otp_code:
            return Response({
                "statuse":"error", "message": WARNING_MESSAGES["MISSING_FIELDS"]},
                status=status.HTTP_400_BAD_REQUEST
            )

        otp_entry = OTP.objects.filter(phone_number=phone_number).first()
        if not otp_entry:
            return Response({
                "status": "warning", "message": WARNING_MESSAGES["OTP_EXPIRED"]},
                status=status.HTTP_400_BAD_REQUEST)

        # bloklanganmi tekshirish
        if otp_entry.is_blocked:
            if otp_entry.blocked_until and otp_entry.blocked_until > timezone.now():
                return Response(
                    {"stats": "error", "message": ERROR_MESSAGES["TOO_MANY_ATTEMPTS"]},
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
            return Response(
                {"status": "error", "message": ERROR_MESSAGES["OTP_EXPIRED"]},
                status=status.HTTP_400_BAD_REQUEST)



        # OTP tekshirish
        if otp_entry.otp_code != otp_code:
            otp_entry.attempts += 1
            if otp_entry.attempts >= MAX_ATTEMPTS:
                otp_entry.is_blocked = True
                otp_entry.blocked_until = timezone.now() + timedelta(minutes=BLOCK_MINUTES)
            otp_entry.save()
            attempts_left = MAX_ATTEMPTS - otp_entry.attempts
            return Response(
                {"status": "error", "message":f"{ERROR_MESSAGES['INCORRECT_OTP']} You have{attempts_left} attempts left."},
                status=status.HTTP_400_BAD_REQUEST)

        # to‘g‘ri bo‘lsa
        user = CustomUser.objects.filter(primary_mobile=phone_number).first()
        if user:
            user.phone_verified = True
            user.save()
        else:
            return Response(
                {"status": "error",
                 "message": ERROR_MESSAGES["USER_NOT_FOUND"]},
                  status=status.HTTP_400_BAD_REQUEST)

        otp_entry.delete()
        return Response(
            {"status": "success",
             "message": SUCCESS_MESSAGES["MOBILE_VALIDATED"]},
            status=status.HTTP_200_OK)



class ResentOTPView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(request_body=ResentOTPSerializers, security=[])
    def post(self, request):
        token = request.data.get("cf-turnstile-response")
        if not token or not verify_turnstile(token, request.META.get('REMOTE_ADDR')):
            return Response({
                "status": "error",
                "message": ERROR_MESSAGES["SYSTEM_ERROR"]
            }, status=status.HTTP_400_BAD_REQUEST)

        serializer = ResentOTPSerializers(data=request.data)
        serializer.is_valid(raise_exception=True)

        phone_number = serializer.validated_data["primary_mobile"]

        #oxirgi otpni olish uchun
        user_exists = CustomUser.objects.filter(primary_mobile=phone_number).exists()
        if not user_exists:
            return Response({
                "status": "error",
                "message": ERROR_MESSAGES["ACCOUNT_NOT_FOUND"]},
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
                "status": "success",
                "message": SUCCESS_MESSAGES["OTP_SENT"],
                "expiry": "5 minutes"
            },
            status=status.HTTP_200_OK
        )



# views.py
class LoginView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        return Response({
            "username_or_phone": "user@example.com",
            "password": "userpassword",
            "remember_me": True,
            "cf-turnstile-response": "TOKEN_HERE"
        })

    @swagger_auto_schema(request_body=LoginSerializer)
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                "message": ERROR_MESSAGES["LOGIN_CREDENTIALS_INCORRECT"]
            },status=status.HTTP_400_BAD_REQUEST)

        user = serializer.validated_data['user']
        remember_me = serializer.validated_data['remember_me']

        #2FA YOQILGANMI? Shuni tekshiramiz
        if getattr(user, "is_2fa_enabled", False):
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
                "message": SUCCESS_MESSAGES.get("VERIFICATION_ACCEPTED","2fa verification required"),
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
            "message": SUCCESS_MESSAGES["LOGIN_SUCCESS"],
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
            if not refresh_token:
                return Response({
                    "messge": ERROR_MESSAGES["SYSTEM_ERROR"]
                },status=status.HTTP_400_BAD_REQUEST)

            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({
                "message": SUCCESS_MESSAGES["LOGGED_OUT"]
            }, status=status.HTTP_205_RESET_CONTENT)
        except Exception:
            return Response({
                "message": ERROR_MESSAGES["SYSTEM_ERROR"]
            }, status=status.HTTP_400_BAD_REQUEST)


class RefreshTokenView(APIView):
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(request_body=RefreshTokenSerializers)
    def post(self, request):
        serializer = RefreshTokenSerializers(data=request.data)
        serializer.is_valid(raise_exception=True)

        refresh_token = serializer.validated_data['refresh']
        try:
            token = RefreshToken(refresh_token)
            new_access = str(token.access_token)
            return Response({
                "access": new_access
                }, status=status.HTTP_200_OK)
        except Exception:
            return Response({
                "message":ERROR_MESSAGES["SYSTEM_ERROR"]
            }, status=status.HTTP_400_BAD_REQUEST)



class Enable2FAView(generics.UpdateAPIView):
    serializer_class = Enable2FASerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user
    @swagger_auto_schema(request_body=Enable2FASerializer)
    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        try:
            serializer.is_valid(raise_exception=True)
        except Exception:
            return Response({
                "message": ERROR_MESSAGES["SYSTEM_ERROR"]
            }, status=400)
        serializer.save()

        return Response({
            "message": SUCCESS_MESSAGES["VERIFICATION_ACCEPTED"],
            "backup_codes": serializer.instance.backup_codes
        }, status=200)



class TwoFAVerifyBackupView(APIView):
    permission_classes = [permissions.AllowAny]
    def get(self, request):
        return Response({
              "session_id": "uuid-from-login-response",
              "backup_code": "ABC123"
            })

    @swagger_auto_schema(request_body=TwoFABackupVerifySerializer)
    def post(self, request):
        serializer = TwoFABackupVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        session_id = serializer.validated_data["session_id"]
        backup_code = serializer.validated_data["backup_code"]

        try:
            session = TwoALoginSession.objects.get(session_id=session_id, is_verified=False)
        except TwoALoginSession.DoesNotExist:
            return Response({
                "message": ERROR_MESSAGES["ACCOUNT_NOT_FOUND"]},
                 status=400)

        if session.is_expired():
            return Response({
                "message": ERROR_MESSAGES["OTP_EXPIRED"]
            }, status=400)

        user = session.user

        if backup_code not in user.backup_codes:
            return  Response({
                "message": ERROR_MESSAGES["INCORRECT_OTP"]
            }, status=400)


        user.backup_codes.remove(backup_code)
        user.save()


        refresh = RefreshToken.for_user(user)

        return Response({
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "message": SUCCESS_MESSAGES["VERIFICATION_ACCEPTED"]
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

























