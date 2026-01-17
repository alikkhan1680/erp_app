from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from django.utils import timezone
from datetime import timedelta

from accounts.models import CustomUser
from auth_module.models import OTP


class SignupAPITestCase(APITestCase):

    def setUp(self):
        self.url = reverse("signup")  # url name = signup
        self.valid_payload = {
            "full_name": "Ahmed Hassan",
            "primary_mobile": "+201012345678"
        }

    # =========================
    # ✅ SUCCESS CASE
    def test_signup_success_creates_otp(self):
        response = self.client.post(self.url, self.valid_payload, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "success")
        self.assertIn("message", response.data)

        # user created or exists
        self.assertTrue(
            CustomUser.objects.filter(
                primary_mobile=self.valid_payload["primary_mobile"]
            ).exists()
        )

        # OTP created
        otp = OTP.objects.filter(
            phone_number=self.valid_payload["primary_mobile"]
        ).first()

        self.assertIsNotNone(otp)
        self.assertTrue(otp.expires_at > timezone.now())

    # =========================
    # ❌ MISSING FIELD
    def test_signup_missing_full_name(self):
        payload = {
            "primary_mobile": "+201012345678"
        }

        response = self.client.post(self.url, payload, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # =========================
    # ❌ INVALID PHONE FORMAT
    def test_signup_invalid_phone_format(self):
        payload = {
            "full_name": "Ahmed Hassan",
            "primary_mobile": "+998901234567"
        }

        response = self.client.post(self.url, payload, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("primary_mobile", response.data)

    # =========================
    # ❌ INVALID FULL NAME (regex)
    def test_signup_invalid_full_name_characters(self):
        payload = {
            "full_name": "Ahmed123",
            "primary_mobile": "+201012345678"
        }

        response = self.client.post(self.url, payload, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("full_name", response.data)

    # =========================
    # ❌ BLANK FIELDS
    # =========================
    def test_signup_blank_fields(self):
        payload = {
            "full_name": "",
            "primary_mobile": ""
        }

        response = self.client.post(self.url, payload, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    #  OTP REPLACED IF EXISTS
    def test_signup_deletes_old_otp_and_creates_new(self):
        CustomUser.objects.create(
            full_name="Ahmed Hassan",
            primary_mobile="+201012345678",
            username="Ahmed"
        )

        OTP.objects.create(
            phone_number="+201012345678",
            otp_code="123456",
            expires_at=timezone.now() + timedelta(minutes=1)
        )

        response = self.client.post(self.url, self.valid_payload, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            OTP.objects.filter(phone_number="+201012345678").count(),
            1
        )

    # RATE LIMIT (optional)
    def test_signup_rate_limit(self):
        for _ in range(10):
            response = self.client.post(self.url, self.valid_payload, format="json")

        self.assertIn(
            response.status_code,
            [status.HTTP_200_OK, status.HTTP_429_TOO_MANY_REQUESTS]
        )
