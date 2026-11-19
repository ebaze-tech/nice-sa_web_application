from rest_framework.permissions import BasePermission

from .models import User


class IsAdminRole(BasePermission):
    message = "You do not have permission to perform this action."

    def has_permission(self, request, view):
        user = request.user
        return bool(user and user.is_authenticated and user.is_active and user.role == User.Role.ADMIN)


class IsStudentRole(BasePermission):
    message = "You do not have permission to perform this action."

    def has_permission(self, request, view):
        user = request.user
        return bool(user and user.is_authenticated and user.is_active and user.role == User.Role.STUDENT)


class IsOfficerRole(BasePermission):
    message = "You do not have permission to perform this action."

    def has_permission(self, request, view):
        user = request.user
        return bool(user and user.is_authenticated and user.is_active and user.role == User.Role.OFFICER)


class HasNicesaPermission(BasePermission):
    message = "You do not have permission to perform this action."

    def has_permission(self, request, view):
        user = request.user
        if not user or not user.is_authenticated or not user.is_active:
            return False
        if user.role == User.Role.ADMIN:
            return True
        required = getattr(view, "required_permission", None)
        if required and "." not in required:
            required = f"accounts.{required}"
        return bool(required and user.role == User.Role.OFFICER and user.has_perm(required))
