from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from unittest.mock import patch, MagicMock
from django.test import override_settings
from core.exceptions import BusinessException

@patch("accounts.views.RegisterOwnerView.throttle_classes", [])
class RegisterOwnerAPITestCase(APITestCase):

    def setUp(self):
        self.url = reverse("register-owner")
        self.payload = {
            "full_name": "John Doe",
            "primary_mobile": "+201012345678",
            "password": "StrongPass1!"
        }

    @patch("accounts.views.UserService.update_existing_user")
    def test_register_owner_success(self, mock_update):
        mock_update.return_value = MagicMock()

        response = self.client.post(self.url, self.payload)

        self.assertEqual(response.status_code, 200)

    @patch("accounts.views.UserService.update_existing_user")
    def test_business_exception(self, mock_update):
        mock_update.side_effect = BusinessException("Already owner")

        response = self.client.post(self.url, self.payload)

        self.assertEqual(response.status_code, 400)


    @patch("accounts.views.UserService.update_existing_user")
    def test_value_error(self, mock_update):
        mock_update.side_effect = ValueError("Invalid data")

        response = self.client.post(self.url, self.payload)

        self.assertEqual(response.status_code, 400)

    @patch("accounts.views.UserService.update_existing_user")
    def test_permission_error(self, mock_update):
        mock_update.side_effect = PermissionError("Forbidden")

        response = self.client.post(self.url, self.payload)

        self.assertEqual(response.status_code, 403)

    @patch("accounts.views.UserService.update_existing_user")
    def test_unexpected_exception(self, mock_update):
        mock_update.side_effect = Exception("Boom")

        response = self.client.post(self.url, self.payload)

        self.assertEqual(response.status_code, 500)

