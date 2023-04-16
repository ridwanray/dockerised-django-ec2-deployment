from rest_framework import permissions

from .enums import SystemRoleEnum


class IsSuperAdmin(permissions.BasePermission):
    """Allows access only to super admin users."""
    message = "Only Super Admins are authorized to perform this action."
    
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        return request.user.roles.filter(name=SystemRoleEnum.SuperAdmin).exists()

class IsAdmin(permissions.BasePermission):
    message = "Only Admins are authorized to perform this action."

    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        return request.user.roles.filter(name=SystemRoleEnum.ADMIN).exists()
