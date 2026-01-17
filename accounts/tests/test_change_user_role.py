from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied

User = get_user_model()


class ChangeUserRoleAPITestCase(APITestCase):

    def setUp(self):
        self.admin = User.objects.create(
            username="admin",
            primary_mobile="+201000000001"
        )
        self.admin.set_password("admin12345")
        self.admin.save()

        self.target_user = User.objects.create(
            username="user1",
            primary_mobile="+201000000002"
        )
        self.target_user.set_password("user12345")
        self.target_user.save()

        self.url = reverse(
            "change_user_role",
            args=[self.target_user.id]
        )

    # ✅ SUCCESS
    @patch("accounts.views.RoleService.change_user_role")
    def test_change_role_success(self, mock_change):
        mock_change.return_value = self.target_user

        self.client.force_authenticate(user=self.admin)

        response = self.client.post(self.url, {
            "new_role": "manager"
        })

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("Role", response.data["msg"])

    # ❌ new_role yo‘q
    def test_new_role_missing(self):
        self.client.force_authenticate(user=self.admin)

        response = self.client.post(self.url, {})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # ❌ PermissionDenied
    @patch("accounts.views.RoleService.change_user_role")
    def test_permission_denied(self, mock_change):
        mock_change.side_effect = PermissionDenied("Not allowed")

        self.client.force_authenticate(user=self.admin)

        response = self.client.post(self.url, {
            "new_role": "admin"
        })

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    # ❌ ValueError (noto‘g‘ri role)
    @patch("accounts.views.RoleService.change_user_role")
    def test_invalid_role(self, mock_change):
        mock_change.side_effect = ValueError("Invalid role")

        self.client.force_authenticate(user=self.admin)

        response = self.client.post(self.url, {
            "new_role": "unknown"
        })

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # ❌ Unauthorized
    def test_unauthorized(self):
        response = self.client.post(self.url, {
            "new_role": "manager"
        })

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
