from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from django.utils import timezone
from datetime import timedelta
import uuid
import pyotp

from accounts.models import CustomUser, TwoALoginSession


class TwoFAVerifyCodeAPITestCase(APITestCase):

    def setUp(self):
        self.url = reverse("2fa-verify-code")

        self.user = CustomUser.objects.create(
            username="testuser",
            primary_mobile="+201012345678",
            is_2fa_enabled=True,
            two_fa_type="AUTHENTICATOR",
        )
        self.user.set_password("StrongPass123")
        self.user.two_fa_secret = pyotp.random_base32()
        self.user.save()

        self.session = TwoALoginSession.objects.create(
            user=self.user,
            is_verified=False,
            created_at=timezone.now()
        )

    def test_twofa_code_verify_success(self):
        totp = pyotp.TOTP(self.user.two_fa_secret)
        code = totp.now()

        response = self.client.post(self.url, {
            "session_id": str(self.session.session_id),
            "code": code
        })

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)

        self.session.refresh_from_db()
        self.assertTrue(self.session.is_verified)

    def test_session_not_found(self):
        response = self.client.post(self.url, {
            "session_id": str(uuid.uuid4()),
            "code": "123456"
        })

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_session_expired(self):
        self.session.created_at = timezone.now() - timedelta(minutes=10)
        self.session.save()

        response = self.client.post(self.url, {
            "session_id": str(self.session.session_id),
            "code": "123456"
        })

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_invalid_totp_code(self):
        response = self.client.post(self.url, {
            "session_id": str(self.session.session_id),
            "code": "000000"
        })

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_sms_2fa_not_implemented(self):
        self.user.two_fa_type = "SMS"
        self.user.save()

        response = self.client.post(self.url, {
            "session_id": str(self.session.session_id),
            "code": "123456"
        })

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_invalid_serializer_data(self):
        response = self.client.post(self.url, {
            "code": "123456"
        })

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
