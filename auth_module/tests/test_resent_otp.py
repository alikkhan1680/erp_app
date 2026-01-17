from django.urls import reverse
from django.utils import timezone
from django.test import override_settings
from rest_framework import status
from rest_framework.test import APITestCase
from unittest.mock import patch

from auth_module.models import OTP
from accounts.models import CustomUser
from datetime import timedelta


@override_settings(
    REST_FRAMEWORK={
        "DEFAULT_THROTTLE_CLASSES": [],
        "DEFAULT_THROTTLE_RATES": {},
    }
)
@patch("auth_module.views.ResentOTPView.throttle_classes", [])
class ResentOTPAPITestCase(APITestCase):

    def setUp(self):
        self.url = reverse("resent-otp")
        self.phone = "+201012345678"
        self.token = "valid-turnstile-token"

        self.user = CustomUser.objects.create(
            username="testuser",
            primary_mobile=self.phone
        )

    # ❌ Turnstile token yo‘q
    @patch("auth_module.views.verify_turnstile", return_value=False)
    def test_missing_turnstile_token(self, mock_turnstile):
        response = self.client.post(self.url, {
            "primary_mobile": self.phone
        }, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["status"], "error")

    # ❌ Turnstile invalid
    @patch("auth_module.views.verify_turnstile", return_value=False)
    def test_invalid_turnstile(self, mock_turnstile):
        response = self.client.post(self.url, {
            "primary_mobile": self.phone,
            "cf-turnstile-response": "invalid"
        }, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # ❌ Noto‘g‘ri phone format
    @patch("auth_module.views.verify_turnstile", return_value=True)
    def test_invalid_phone_format(self, mock_turnstile):
        response = self.client.post(self.url, {
            "primary_mobile": "123",
            "cf-turnstile-response": self.token
        }, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # ❌ User topilmadi
    @patch("auth_module.views.verify_turnstile", return_value=True)
    def test_user_not_found(self, mock_turnstile):
        response = self.client.post(self.url, {
            "primary_mobile": "+201011111111",
            "cf-turnstile-response": self.token
        }, format="json")

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    # ✅ OTP resend success
    @patch("auth_module.views.verify_turnstile", return_value=True)
    def test_resent_otp_success(self, mock_turnstile):
        response = self.client.post(self.url, {
            "primary_mobile": self.phone,
            "cf-turnstile-response": self.token
        }, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "success")

        otp = OTP.objects.filter(phone_number=self.phone).first()
        self.assertIsNotNone(otp)
        self.assertFalse(otp.is_blocked)
        self.assertEqual(otp.attempts, 0)
