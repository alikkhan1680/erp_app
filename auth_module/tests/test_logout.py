from rest_framework.test import APITestCase
from rest_framework import status
from django.urls import reverse
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model

User = get_user_model()


class LogoutAPITestCase(APITestCase):

    def setUp(self):
        self.url = reverse("logoute")

        self.user = User.objects.create(
            username="testuser",
            primary_mobile="+201012345678"
        )
        self.user.set_password("TestPassword123")
        self.user.save()

        self.refresh = RefreshToken.for_user(self.user)
        self.access = str(self.refresh.access_token)

        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {self.access}"
        )

    def test_logout_success(self):
        response = self.client.post(self.url, {
            "refresh": str(self.refresh)
        })

        self.assertEqual(response.status_code, status.HTTP_205_RESET_CONTENT)
        self.assertEqual(response.data["message"], "You have logged out successfully.")

    def test_logout_without_refresh_token(self):
        response = self.client.post(self.url, {})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_logout_invalid_refresh_token(self):
        response = self.client.post(self.url, {
            "refresh": "invalid.token.value"
        })

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_logout_unauthenticated(self):
        self.client.credentials()  # auth olib tashlanadi

        response = self.client.post(self.url, {
            "refresh": str(self.refresh)
        })

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
