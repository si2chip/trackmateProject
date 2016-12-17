from rest_framework import permissions


class IsUsrOwner(permissions.BasePermission):
    def has_object_permission(self, request, view, usr):
        if request.user:
            return usr == request.user
        return False