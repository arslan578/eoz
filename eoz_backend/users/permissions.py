from rest_framework import permissions

AGENT_TYPE = (
        (1, 1),  # education_agen
        (2, 2),  # migration_agent
        (3, 3),  # accountant_agent
        (4, 4),  # natti_translator_agent
        (5, 5),  # none
    )


class AdminPermission(permissions.BasePermission):

    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.is_active and request.user.is_superuser


class AllAgentPermission(permissions.BasePermission):

    def has_permission(self, request, view):
        return ((request.user.is_authenticated and request.user.is_active) and (request.user.agent_type == 4
                or request.user.agent_type == 3 or request.user.agent_type == 1
                or request.user.agent_type == 2))


class ClientPermission(permissions.BasePermission):

    def has_permission(self, request, view):
        return (request.user.is_authenticated and request.user.is_active and
                not request.user.is_agent and request.user.agent_type == 0)
