from unittest.mock import patch

from django.test import override_settings
from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from django.utils import timezone
from datetime import timedelta
from auth_module.models import OTP
from accounts.models import CustomUser

MAX_ATTEMPTS = 3
BLOCK_MINUTES = 15
OTP_EXPIRY_MINUTES = 5

@override_settings(REST_FRAMEWORK={"DEFAULT_THROTTLE_CLASSES": [],"DEFAULT_THROTTLE_RATES": {},})
@patch("auth_module.views.OTPVerifyView.throttle_classes", [])
class OTPVerifyAPITestCase(APITestCase):

    def setUp(self):
        self.url = reverse("verify-otp")  # urls.py dagi name
        self.phone = "+201012345678"
        self.otp_code = "123456"

        self.user = CustomUser.objects.create(
            username="Ahmed",
            full_name="Ahmed Hassan",
            primary_mobile=self.phone,
            phone_verified=False
        )

    # =========================
    # ✅ SUCCESS CASE
    def test_otp_verify_success(self):
        OTP.objects.create(
            phone_number=self.phone,
            otp_code=self.otp_code,
            expires_at=timezone.now() + timedelta(minutes=5)
        )

        response = self.client.post(self.url, {
            "primary_mobile": self.phone,
            "otp_code": self.otp_code
        }, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertTrue(self.user.phone_verified)
        self.assertFalse(OTP.objects.filter(phone_number=self.phone).exists())

    # =========================
    # ❌ OTP NOT FOUND
    def test_otp_not_found(self):
        response = self.client.post(self.url, {
            "primary_mobile": self.phone,
            "otp_code": self.otp_code
        }, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # =========================
    # ❌ OTP EXPIRED
    def test_otp_expired(self):
        OTP.objects.create(
            phone_number=self.phone,
            otp_code=self.otp_code,
            expires_at=timezone.now() - timedelta(minutes=1)
        )

        response = self.client.post(self.url, {
            "primary_mobile": self.phone,
            "otp_code": self.otp_code
        }, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(OTP.objects.filter(phone_number=self.phone).exists())

    # =========================
    # ❌ INCORRECT OTP
    def test_incorrect_otp_increments_attempts(self):
        otp = OTP.objects.create(
            phone_number=self.phone,
            otp_code="654321",
            expires_at=timezone.now() + timedelta(minutes=5),
            attempts=0
        )

        response = self.client.post(self.url, {
            "primary_mobile": self.phone,
            "otp_code": self.otp_code
        }, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        otp.refresh_from_db()
        self.assertEqual(otp.attempts, 1)

    # =========================
    #  BLOCK AFTER MAX ATTEMPTS
    def test_otp_block_after_max_attempts(self):
        otp = OTP.objects.create(
            phone_number=self.phone,
            otp_code="654321",
            expires_at=timezone.now() + timedelta(minutes=5),
            attempts=MAX_ATTEMPTS - 1
        )

        response = self.client.post(self.url, {
            "primary_mobile": self.phone,
            "otp_code": self.otp_code
        }, format="json")

        otp.refresh_from_db()
        self.assertTrue(otp.is_blocked)
        self.assertIsNotNone(otp.blocked_until)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # =========================
    #  BLOCKED OTP (ACTIVE)
    def test_blocked_otp_active(self):
        OTP.objects.create(
            phone_number=self.phone,
            otp_code=self.otp_code,
            expires_at=timezone.now() + timedelta(minutes=5),
            is_blocked=True,
            blocked_until=timezone.now() + timedelta(minutes=5)
        )

        response = self.client.post(self.url, {
            "primary_mobile": self.phone,
            "otp_code": self.otp_code
        }, format="json")

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    # =========================
    # ❌ USER NOT FOUND
    def test_user_not_found(self):
        CustomUser.objects.filter(primary_mobile=self.phone).delete()

        OTP.objects.create(
            phone_number=self.phone,
            otp_code=self.otp_code,
            expires_at=timezone.now() + timedelta(minutes=5)
        )

        response = self.client.post(self.url, {
            "primary_mobile": self.phone,
            "otp_code": self.otp_code
        }, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # =========================
    # ❌ INVALID PAYLOAD (SERIALIZER)
    def test_invalid_serializer_data(self):
        response = self.client.post(self.url, {
            "primary_mobile": "998901234567",
            "otp_code": "12ab"
        }, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
