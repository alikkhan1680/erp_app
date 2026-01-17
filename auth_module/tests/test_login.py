from django.urls import reverse
from django.test import override_settings
from rest_framework.test import APITestCase
from rest_framework import status
from unittest.mock import patch

from auth_module.models import  LoginActivity
from accounts.models import CustomUser

@override_settings(
    TEST_MODE=True,
    REST_FRAMEWORK={
        "DEFAULT_THROTTLE_CLASSES": [],
        "DEFAULT_THROTTLE_RATES": {},
    }
)
@patch("auth_module.views.LoginView.throttle_classes", [])
class LoginAPITestCase(APITestCase):

    def setUp(self):
        self.url = reverse("login")
        self.password = "StrongPass123"

        self.user = CustomUser.objects.create(
            username="testuser",
            primary_mobile="+201012345678",
            email="test@test.com",
            user_role="employee"
        )
        self.user.set_password(self.password)
        self.user.save()

    # ❌ Wrong password
    def test_login_invalid_credentials(self):
        response = self.client.post(self.url, {
            "username_or_phone": "testuser",
            "password": "WrongPass123",
            "cf_turnstile_response": "test"
        }, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 1)

    # ❌ User not found
    def test_login_user_not_found(self):
        response = self.client.post(self.url, {
            "username_or_phone": "nouser",
            "password": "WrongPass123",
            "cf_turnstile_response": "test"
        }, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # ✅ Login success (no 2FA)
    def test_login_success(self):
        response = self.client.post(self.url, {
            "username_or_phone": "testuser",
            "password": self.password,
            "remember_me": False,
            "cf_turnstile_response": "test"
        }, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data["2fa_required"])
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)

        self.assertTrue(
            LoginActivity.objects.filter(user=self.user).exists()
        )

    # ✅ remember_me = True
    def test_login_with_remember_me(self):
        response = self.client.post(self.url, {
            "username_or_phone": "testuser",
            "password": self.password,
            "remember_me": True,
            "cf_turnstile_response": "test"
        }, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    # 🔐 2FA enabled (AUTHENTICATOR)
    def test_login_with_2fa_authenticator(self):
        self.user.is_2fa_enabled = True
        self.user.two_fa_type = "AUTHENTICATOR"
        self.user.two_fa_secret = "JBSWY3DPEHPK3PXP"
        self.user.save()

        response = self.client.post(self.url, {
            "username_or_phone": "testuser",
            "password": self.password,
            "cf_turnstile_response": "test"
        }, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["2fa_required"])
        self.assertIn("session_id", response.data)
        self.assertIn("generated_code", response.data)
