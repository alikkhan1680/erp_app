from ipaddress import ip_address

from django.core.serializers import serialize
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework.permissions import IsAuthenticated
from rest_framework.status import HTTP_400_BAD_REQUEST
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions, serializers
from django.utils import timezone
from datetime import timedelta
import random


from .models import OTP, LoginActivity
from accounts.models import CustomUser
from .serializers import SignupSerializer, OTPVerifyserializers, ResentOTPSerializers, LoginSerializer, TwoFAInitiateSerializers, TwoFAVerifySerializer
from .utilits import verify_turnstile
from .services.twofa_service import TwoFAService

MAX_ATTEMPTS = 5
BLOCK_MINUTES = 15
OTP_EXPIRY_MINUTES = 5


# SIGNUP VIEW
class SignUPView(APIView):
    def get(self, request):
        return Response({
            "message": "Bu endpoint faqat POST uchun. Malumot yuboring: full_name va primary_mobile",
            "cf-turnstile-response": "You can write anything you want right now, it's not in the works yet.",
                "full_name": "full name",
                "primary_mobile": "+998909999999"

        })
    @swagger_auto_schema(request_body=SignupSerializer)
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
    @swagger_auto_schema(request_body=OTPVerifyserializers)
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

    def get(self, request):
        return Response({
            "message": "bu end point resent otp ni tekshirish uchun ",
            "cf-turnstile-response": "You can write anything you want right now, it's not in the works yet."
        })
    @swagger_auto_schema(request_body=ResentOTPSerializers)
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
            attempts=expires_at,
            attampts=0,
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

    @swagger_auto_schema(request_body=LoginSerializer)
    def post(self, request):
        print("Request data:", request.data)  # Step 1

        serializer = LoginSerializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except serializers.ValidationError as e:
            print("Serializer error:", e)  # Step 2
            raise

        user = serializer.validated_data['user']
        remember_me = serializer.validated_data['remember_me']
        print("User found:", user)  # Step 3

        # 🔹 Token yaratish
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
            "user_role": user.user_role
        }, status=status.HTTP_200_OK)

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip



class LogouteView(APIView):
    # permission_classes = [permissions.IsAuthenticated]

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
    swagger_auto_schema(request_body="refresh")
    def post(self, request):
        try:
            refresh_token = request.data['refresh']
            token = RefreshToken(refresh_token)
            new_access = str(token.access_token)
            return Response({"access": new_access})
        except Exception as e:
            return Response({"errors": str(e)}, status=HTTP_400_BAD_REQUEST)


class TwoFAEnableInitiateView(APIView):
    permission_classes = [IsAuthenticated]
    swagger_auto_schema(request_body=TwoFAInitiateSerializers)
    def post(self, request):
        user = request.user

        if user.is_2fa_enabled:
            return Response({"message": "2FA already enabled"}, status=400)

        secret = TwoFAService.generate_secret()
        user.two_fa_secret = secret
        user.save(update_fields=["two_fa_secret"])

        qr_url = TwoFAService.generate_qr_uri(user.email, secret, app_name="MyApp")

        serializer = TwoFAInitiateSerializers({"qr_url": qr_url, "secret": secret})
        return Response(serializer.data)


class TwoFAEnableVerifyView(APIView):
    permission_classes = [IsAuthenticated]
    swagger_auto_schema(request_body=TwoFAVerifySerializer)
    def post(self, request):
        user = request.user
        serializer = TwoFAVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        code = serializer.validated_data["code"]

        success, result = TwoFAService.enable_2fa(user, code)
        if not success:
            return Response({"message": result}, status=400)

        return Response({
            "message": "2FA enabled successfully",
            "backup_codes": result  # foydalanuvchiga ko‘rsatish uchun
        })



class Login2FAVerifyView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    swagger_auto_schema(request_body=JWTAuthentication)
    def post(self, request):
        user = request.user
        code = request.data.get("code")

        if not user.is_2fa_enabled:
            return Response({"message": "2FA not enabled"}, status=400)

        valid = TwoFAService.verify_totp_code(user.two_fa_secret, code)
        if not valid:
            return Response({"message": "Invalid 2FA code"}, status=400)

        # muvaffaqiyatli → JWT qaytarish
        refresh = RefreshToken.for_user(user)
        return Response({
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "message": "2FA login successful"
        })
























