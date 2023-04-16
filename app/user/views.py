from datetime import datetime, timezone

from core.pagination import CustomPagination
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404
from django.utils.crypto import get_random_string
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema, inline_serializer
from rest_framework import filters, serializers, status, viewsets
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.settings import api_settings
from rest_framework_simplejwt.views import TokenObtainPairView

from .enums import SystemRoleEnum, TokenEnum
from .filters import UserFilter
from .models import Token, User
from .permissions import IsAdmin, IsSuperAdmin
from .serializers import (AuthTokenSerializer,
                          CreatePasswordFromTokenSerializer,
                          CreateUserSerializer,
                          CustomObtainTokenPairSerializer, EmailSerializer,
                          ListUserSerializer,  PasswordChangeSerializer,
                          TokenDecodeSerializer,
                          UpdateUserSerializer)
from .tasks import send_password_reset_email
from .utils import create_token_and_send_user_email, get_user_role_names


class CustomObtainTokenPairView(TokenObtainPairView):
    """Authentice with email and password"""
    serializer_class = CustomObtainTokenPairSerializer


class AuthViewsets(viewsets.GenericViewSet):
    """Auth viewsets"""
    serializer_class = EmailSerializer
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        permission_classes = self.permission_classes
        if self.action in ["initiate_password_reset", "create_password", "verify_account"]:
            permission_classes = [AllowAny]
        return [permission() for permission in permission_classes]

    @action(
        methods=["POST"],
        detail=False,
        serializer_class=EmailSerializer,
        url_path="initiate-password-reset",
    )
    def initiate_password_reset(self, request, pk=None):
        """Send temporary password to user email"""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = request.data["email"].lower().strip()
        user = get_user_model().objects.filter(email=email, is_active=True).first()
        if not user:
            return Response({"success": False, "message": "No active account found!"}, status=400)

        token, _ = Token.objects.update_or_create(
            user=user,
            token_type=TokenEnum.PASSWORD_RESET,
            defaults={
                "user": user,
                "token_type": TokenEnum.PASSWORD_RESET,
                "token": get_random_string(20),
                "created_at": datetime.now(timezone.utc)
            }
        )

        email_data = {
            "fullname": user.firstname,
            "email": user.email,
            "token": f"{token.token}",
        }
        send_password_reset_email.delay(email_data)

        return Response({"success": True,
                         "message": "Temporary password sent to your email!"}, status=200)

    @action(methods=['POST'], detail=False, serializer_class=CreatePasswordFromTokenSerializer, url_path='create-password')
    def create_password(self, request, pk=None):
        """Create a new password given the reset token"""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token: Token = Token.objects.filter(
            token=request.data['token'],  token_type=TokenEnum.PASSWORD_RESET).first()
        if not token or not token.is_valid():
            return Response({'success': False, 'errors': 'Invalid token specified'}, status=400)
        token.reset_user_password(request.data['new_password'])
        token.delete()
        return Response({'success': True, 'message': 'Password successfully reset'}, status=status.HTTP_200_OK)

    @extend_schema(
        responses={
            200: inline_serializer(
                name='AccountVerificationStatus',
                fields={
                    "success": serializers.BooleanField(default=True),
                    "message": serializers.CharField(default="Acount Verification Successful")
                }
            ),
        },
    )
    @action(
        methods=["POST"],
        detail=False,
        serializer_class=TokenDecodeSerializer,
        url_path="verify-account",
    )
    def verify_account(self, request, pk=None):
        """Activate a user acount using the token sent to the user"""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token: Token = Token.objects.filter(
            token=request.data['token'],  token_type=TokenEnum.ACCOUNT_VERIFICATION).first()
        if not token or not token.is_valid():
            return Response({'success': False, 'errors': 'Invalid token specified'}, status=400)
        token.verify_user()
        token.delete()
        return Response({"success": True, "message": "Acount Verification Successful"}, status=200)


class PasswordChangeView(viewsets.GenericViewSet):
    '''Allows password change to authenticated user.'''
    serializer_class = PasswordChangeSerializer
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        context = {"request": request}
        serializer = self.get_serializer(data=request.data, context=context)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"message": "Your password has been updated."}, status.HTTP_200_OK)


class CreateTokenView(ObtainAuthToken):
    """Create a new auth token for user"""

    serializer_class = AuthTokenSerializer
    renderer_classes = api_settings.DEFAULT_RENDERER_CLASSES

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        try:
            token, created = Token.objects.get_or_create(user=user)
            return Response(
                {"token": token.key, "created": created, "roles": user.roles},
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            return Response({"message": str(e)}, 500)


class UserViewsets(viewsets.ModelViewSet):
    queryset = get_user_model().objects.all().prefetch_related(
        'roles').select_related('created_by')
    serializer_class = ListUserSerializer
    permission_classes = [IsAuthenticated]
    http_method_names = ["get", "post", "patch", "delete"]
    filter_backends = [
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter,
    ]
    filterset_class = UserFilter
    search_fields = ["email", "firstname", "lastname", "phone"]
    ordering_fields = [
        "created_at",
        "email",
        "firstname",
        "lastname",
        "phone",
    ]

    def get_queryset(self):
        user: User = self.request.user
        if SystemRoleEnum.ADMIN in get_user_role_names(user):
            return get_user_model().objects.all()
        return super().get_queryset().filter(id=user.id)

    def get_serializer_class(self):
        if self.action in ["create"]:
            return CreateUserSerializer
        if self.action in ["partial_update", "update"]:
            return UpdateUserSerializer
        return super().get_serializer_class()

    def get_permissions(self):
        permission_classes = self.permission_classes
        if self.action in ["create"]:
            permission_classes = [IsAdmin | IsSuperAdmin]
        elif self.action in ["reinvite_user", "onboard_hirer", "onboard_talent"]:
            permission_classes = [AllowAny]
        elif self.action in ["list", "retrieve", "partial_update", "update"]:
            permission_classes = [IsAuthenticated]
        elif self.action in ["destroy"]:
            permission_classes = [IsSuperAdmin | IsAdmin]
        return [permission() for permission in permission_classes]

    def list(self, request, *args, **kwargs):
        "Retrieve user lists based on assigned role"
        return super().list(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        """Only an Admin can create a user directly on the system"""
        return super().create(request, *args, **kwargs)

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

    def _reinvite_check(self, request):
        email: str = request.data["email"].lower().strip()
        user: User = get_object_or_404(User, email=email)
        if user.verified:
            return None
        else:
            return user

    @action(
        methods=["POST"],
        detail=False,
        serializer_class=EmailSerializer,
        url_path="resend-verification",
    )
    def reinvite_user(self, request, *args, **kwargs):
        '''Resend verification email to a user'''
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = self._reinvite_check(request)
        if not user:
            return Response({"success": False, "message": "User already verified"}, status.HTTP_400_BAD_REQUEST)
        create_token_and_send_user_email(
            user=user, token_type=TokenEnum.ACCOUNT_VERIFICATION)
        return Response({"success": True, "message": "Verification mail sent successfully."}, status.HTTP_200_OK)
