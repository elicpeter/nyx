from django.urls import path


class LoginRequiredMixin:
    pass


class PermissionRequiredMixin:
    pass


class View:
    @classmethod
    def as_view(cls):
        return cls


class AdminService:
    def update_user_role(self, user_id, role):
        return None


admin_service = AdminService()


class AdminRoleView(LoginRequiredMixin, PermissionRequiredMixin, View):
    permission_required = "auth.change_user"

    def post(self, request, user_id):
        admin_service.update_user_role(user_id, request.POST["role"])
        return None


urlpatterns = [
    path("admin/users/<int:user_id>/role/", AdminRoleView.as_view()),
]
