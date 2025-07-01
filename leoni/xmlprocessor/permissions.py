from rest_framework.permissions import BasePermission

class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == "admin"

class IsValidator(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == "validator"

class IsOverseer(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == "overseer"
