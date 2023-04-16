from datetime import timedelta

from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.hashers import make_password
from django.db import transaction
from django.utils.translation import gettext_lazy as _
from rest_framework import exceptions, serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from user.enums import SystemRoleEnum

from .models import Role, User
from .utils import get_user_role_names, validate_role_assignment


class CustomObtainTokenPairSerializer(TokenObtainPairSerializer):

    def validate(self, attrs):
        data = super().validate(attrs)
        options = {"hours": settings.TOKEN_LIFESPAN}
        refresh = self.get_token(self.user)
        access_token = refresh.access_token
        access_token.set_exp(lifetime=timedelta(**options))
        self.user.save_last_login()
        data['refresh'] = str(refresh)
        data['access'] = str(access_token)
        return data

    @classmethod
    def get_token(cls, user):
        if not user.verified:
            raise exceptions.AuthenticationFailed(
                _('Account not verified.'), code='authentication')
        token = super().get_token(user)
        token.id = user.id
        token['firstname'] = user.firstname
        token['lastname'] = user.lastname
        token["email"] = user.email
        token["roles"] = list(user.roles.all().values_list('name', flat=True))
        return token


class AuthTokenSerializer(serializers.Serializer):
    """Serializer for user authentication object"""

    email = serializers.CharField()
    password = serializers.CharField(
        style={"input_type": "password"}, trim_whitespace=False)

    def validate(self, attrs):
        """Validate and authenticate the user"""
        email = attrs.get("email")
        password = attrs.get("password")
        if email:
            user = authenticate(request=self.context.get(
                "request"), username=email.lower().strip(), password=password)

        if not user:
            msg = _("Unable to authenticate with provided credentials")
            raise serializers.ValidationError(msg, code="authentication")
        attrs["user"] = user
        return attrs


class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(max_length=128, required=False)
    new_password = serializers.CharField(max_length=128, min_length=5)

    def validate_old_password(self, value):
        request = self.context["request"]

        if not request.user.check_password(value):
            raise serializers.ValidationError("Old password is incorrect.")
        return value

    def save(self):
        user: User = self.context["request"].user
        new_password = self.validated_data["new_password"]
        user.set_password(new_password)
        user.save(update_fields=["password"])


class CreatePasswordFromTokenSerializer(serializers.Serializer):
    token = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)


class TokenDecodeSerializer(serializers.Serializer):
    token = serializers.CharField(required=True)


class EmailSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)


class ListUserSerializer(serializers.ModelSerializer):
    roles = serializers.SlugRelatedField(
        many=True, queryset=Role.objects.all(), slug_field='name')

    class Meta:
        model = get_user_model()
        fields = [
            "id",
            "firstname",
            "lastname",
            "email",
            "image",
            "verified",
            "created_at",
            "roles",
        ]

        extra_kwargs = {
            "verified": {"read_only": True},
            "roles": {"read_only": True},
        }

    def to_representation(self, instance):
        return super().to_representation(instance)


class UpdateUserSerializer(serializers.ModelSerializer):
    roles = serializers.SlugRelatedField(
        many=True, queryset=Role.objects.all(), slug_field='name',
        error_messages={
            'does_not_exist': "No matching Role found for:'{value}'",
        })

    class Meta:
        model = get_user_model()
        fields = [
            "id",
            "firstname",
            "lastname",
            "image",
            "verified",
            "roles"
        ]
        extra_kwargs = {
            "last_login": {"read_only": True},
            "verified": {"read_only": True},
            "roles": {"required": False},
        }

    def validate(self, attrs: dict):
        """Only allow admin to modify/assign role"""
        auth_user: User = self.context["request"].user
        new_role_assignment = attrs.get("roles", None)
        is_admin = SystemRoleEnum.ADMIN in get_user_role_names(auth_user)
        if new_role_assignment and is_admin:
            validate_role_assignment(self, attrs)
        else:
            attrs.pop('roles', None)
        return super().validate(attrs)

    def update(self, instance, validated_data):
        if validated_data.get("password", False):
            validated_data.pop('password')
        roles = validated_data.pop('roles', None)
        instance = super().update(instance, validated_data)
        if roles is not None:
            instance.roles.clear()
            for role in roles:
                instance.roles.add(role)
        return instance


class BasicUserInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = [
            "firstname",
            "lastname",
        ]


class CreateUserSerializer(serializers.ModelSerializer):
    """Serializer for creating user object"""
    roles = serializers.SlugRelatedField(
        many=True, queryset=Role.objects.all(), slug_field='name')

    class Meta:
        model = get_user_model()
        fields = (
            "id",
            "email",
            "firstname",
            "lastname",
            "verified",
            "phone_number",
            "password",
            "roles",
        )

        extra_kwargs = {
            "last_login": {"read_only": True},
            "verified": {"read_only": True},
            "firstname": {"required": True},
            "lastname": {"required": True},
            "password": {"required": True, "write_only": True},
            "roles": {"required": True},
        }

    def validate(self, attrs):
        result = validate_role_assignment(self, attrs)
        return super().validate(result)

    def validate_email(self, value):
        if value:
            email = value.lower().strip()
            if get_user_model().objects.filter(email=email).exists():
                raise serializers.ValidationError({'email':'Email already exists'})
        return value

    @transaction.atomic
    def create(self, validated_data):
        validated_data["password"] = make_password(validated_data["password"])
        user = User.objects.create_app_user(**validated_data)
        return user
