from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from django.contrib.auth import get_user_model

User = get_user_model()


class Enable2FAAPITestCase(APITestCase):

    def setUp(self):
        self.user = User.objects.create(
            username="testuser",
            primary_mobile="+201012345678"
        )
        self.user.set_password("StrongPass123")
        self.user.save()

        self.url = reverse("enable-2fa")  # urls.py dagi name

    def test_enable_2fa_unauthenticated(self):
        """Auth bo‘lmagan user kira olmasligi kerak"""
        response = self.client.patch(self.url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_enable_2fa_success(self):
        """2FA muvaffaqiyatli yoqiladi"""
        self.client.force_authenticate(user=self.user)

        response = self.client.patch(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("backup_codes", response.data)

        self.user.refresh_from_db()

        self.assertTrue(self.user.is_2fa_enabled)
        self.assertIsNotNone(self.user.two_fa_secret)
        self.assertEqual(len(self.user.backup_codes), 5)

    def test_backup_codes_are_returned(self):
        """Backup code’lar response’da qaytishi kerak"""
        self.client.force_authenticate(user=self.user)

        response = self.client.patch(self.url)

        self.assertEqual(len(response.data["backup_codes"]), 5)
