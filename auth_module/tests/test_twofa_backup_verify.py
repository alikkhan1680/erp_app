from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from unittest.mock import patch
import uuid
from django.utils import timezone
from datetime import timedelta

from accounts.models import CustomUser, TwoALoginSession


class TwoFAVerifyBackupAPITestCase(APITestCase):

    def setUp(self):
        self.url = reverse("2fa-verify-backup")

        self.user = CustomUser.objects.create(
            username="testuser",
            primary_mobile="+201012345678",
            is_2fa_enabled=True,
            backup_codes=["code123", "code456"]
        )
        self.user.set_password("StrongPass123")
        self.user.save()

        self.session = TwoALoginSession.objects.create(
            user=self.user,
            is_verified=False,
            created_at=timezone.now()
        )

    def test_backup_verify_success(self):
        response = self.client.post(self.url, {
            "session_id": str(self.session.session_id),
            "backup_code": "code123"
        })

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)

        self.user.refresh_from_db()
        self.assertNotIn("code123", self.user.backup_codes)

    def test_session_not_found(self):
        response = self.client.post(self.url, {
            "session_id": str(uuid.uuid4()),
            "backup_code": "code123"
        })

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_session_expired(self):
        self.session.created_at = timezone.now() - timedelta(minutes=10)
        self.session.save()

        response = self.client.post(self.url, {
            "session_id": str(self.session.session_id),
            "backup_code": "code123"
        })

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_incorrect_backup_code(self):
        response = self.client.post(self.url, {
            "session_id": str(self.session.session_id),
            "backup_code": "wrong-code"
        })

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_invalid_serializer_data(self):
        response = self.client.post(self.url, {
            "backup_code": "code123"
        })

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
