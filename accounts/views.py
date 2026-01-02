import datetime
from drf_yasg.utils import swagger_auto_schema
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication

from auth_module.serializers import  RegisterOwnerSerializer
from core.exceptions import BusinessException
from .services import UserService, RoleService
from core.messages.error import ERROR_MESSAGES
from core.messages.success import SUCCESS_MESSAGES
from rest_framework.permissions import IsAuthenticated


class RegisterOwnerView(APIView):
    permission_classes = [AllowAny]
    swagger_auto_schema(request_body=RegisterOwnerSerializer)
    def post(self, request):
        serializer = RegisterOwnerSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            user = UserService.update_existing_user(**serializer.validated_data)
        except BusinessException as e:
            return Response(
                {"status":"error",
                 "message": e.message},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception:
            return Response(
                {
                    "status": "error",
                    'message':ERROR_MESSAGES["SYSTEM_ERROR"]},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        return Response(
            {"status":"success",
             "message": SUCCESS_MESSAGES["ASSIGNED_AS_OWNER"]},
            status=status.HTTP_200_OK
        )


class ChangeUserRoleView(APIView):
    # permission_classes = [IsAuthenticated]

    def post(self, request, user_id):
        new_role = request.data.get("new_role")
        user = RoleService.change_user_role(request.user, user_id, new_role)
        return  Response({"msg": f"{user.username} role {user.user_role} ga o'zgartirildi"})


class SessionTestAPIView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        user = request.user
        token = request.auth

        if hasattr(token, 'payload'):
            exp_timestamp = token.payload.get('exp')  # integer
        else:
            exp_timestamp = None

        if exp_timestamp:
            exp_datetime = datetime.datetime.fromtimestamp(exp_timestamp)
        else:
            exp_datetime = None

        return Response({
            "user": str(user),
            "token_expires_at": exp_datetime,
        })
