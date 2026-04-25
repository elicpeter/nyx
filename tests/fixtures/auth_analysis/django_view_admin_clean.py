from django.urls import path


def permission_required(permission_name):
    def decorate(fn):
        return fn

    return decorate


class AdminService:
    def update_user_role(self, user_id, role):
        return None


admin_service = AdminService()


@permission_required("auth.change_user")
def update_user_role(request, user_id):
    admin_service.update_user_role(user_id, request.POST["role"])
    return None


urlpatterns = [
    path("admin/users/<int:user_id>/role/", update_user_role),
]
