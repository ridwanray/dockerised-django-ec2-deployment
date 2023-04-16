from datetime import datetime, timezone
from typing import Any, Dict

from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.utils.crypto import get_random_string
from rest_framework import serializers

from .enums import SystemRoleEnum
from .models import Token, User


def send_email(subject:str, email_to: str, html_alternative: Any, attachment: Dict = None):
    msg = EmailMultiAlternatives(
        subject=subject, from_email=settings.EMAIL_FROM,to= [email_to]
    )
    msg.attach_alternative(html_alternative, "text/html")
    msg.send(fail_silently=False)


def create_token_and_send_user_email(user: User, token_type: str)->None:
    from .tasks import send_user_creation_email
    token, _ = Token.objects.update_or_create(
        user=user,
        token_type=token_type,
        defaults={
            "user": user,
            "token_type": token_type,
            "token": get_random_string(120),
            "created_at": datetime.now(timezone.utc)
        },
    )
    user_data = {
        "email": user.email,
        "fullname": f"{user.firstname}",
        "token": token.token
    }
    send_user_creation_email.delay(user_data)


def get_user_role_names(user)->list:
    """
    Returns a list of role names for the given user.
    """
    return user.roles.values_list('name', flat=True)


def validate_role_assignment(self, attrs: dict)->dict:
    auth_user = self.context["request"].user
    request_roles = [each.name for each in attrs.get('roles')]
    auth_user_role: list[str] = get_user_role_names(auth_user)
    super_admin_allowable_roles: list[str] = ["SuperAdmin","Admin"]
    if SystemRoleEnum.ADMIN in auth_user_role:
            allowable_roles = super_admin_allowable_roles
    elif SystemRoleEnum.SuperAdmin in auth_user_role:
            allowable_roles = super_admin_allowable_roles
    else:
        raise serializers.ValidationError({'user':'Only admin creates accounts or assigns roles!'})
        
    is_valid: bool = all(role in allowable_roles for role in request_roles)
    if not is_valid:
        roles = ','.join(allowable_roles)
        raise serializers.ValidationError({'roles':f'Roles option can only be any of {roles}'})
    return attrs