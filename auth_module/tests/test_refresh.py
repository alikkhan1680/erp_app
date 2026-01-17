from rest_framework.test import APITestCase
from rest_framework import status
from django.urls import reverse
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
from django.test import override_settings

User = get_user_model()


@override_settings(
    REST_FRAMEWORK={
        "DEFAULT_THROTTLE_CLASSES": [],
        "DEFAULT_THROTTLE_RATES": {},
    }
)
class RefreshTokenAPITestCase(APITestCase):

    def setUp(self):
        self.url = reverse("token_refresh")

        self.user = User.objects.create(
            username="refreshuser",
            primary_mobile="+201012345679"
        )
        self.user.set_password("TestPassword123")
        self.user.save()

        self.refresh = RefreshToken.for_user(self.user)

    def test_refresh_token_success(self):
        response = self.client.post(self.url, {
            "refresh": str(self.refresh)
        })

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertEqual(response.data["expires_in"], 3600)

    def test_refresh_token_missing(self):
        response = self.client.post(self.url, {})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_refresh_token_invalid(self):
        response = self.client.post(self.url, {
            "refresh": "invalid.refresh.token"
        })

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_refresh_token_blacklisted(self):
        # refresh tokenni blacklist qilamiz
        self.refresh.blacklist()

        response = self.client.post(self.url, {
            "refresh": str(self.refresh)
        })

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
