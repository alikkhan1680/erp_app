from django.urls import path
from django.http import JsonResponse
from .views import ChangeUserRoleView, RegisterOwnerView, SessionTestAPIView


urlpatterns = [
    path('user/<int:user_id>/change-role/', ChangeUserRoleView.as_view(), name="change_user_role"),
    path("signup-final/", RegisterOwnerView.as_view(), name="register-owner"),
    path('session-tests/', SessionTestAPIView.as_view(), name='session-tests'),
]
