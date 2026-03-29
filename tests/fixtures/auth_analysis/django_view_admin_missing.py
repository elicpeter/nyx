from django.urls import path


def login_required(fn):
    return fn


class AdminService:
    def update_user_role(self, user_id, role):
        return None


admin_service = AdminService()


@login_required
def update_user_role(request, user_id):
    admin_service.update_user_role(user_id, request.POST["role"])
    return None


urlpatterns = [
    path("admin/users/<int:user_id>/role/", update_user_role),
]
