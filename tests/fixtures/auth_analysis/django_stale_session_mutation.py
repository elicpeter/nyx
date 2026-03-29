from django.urls import path


class WorkspaceStore:
    def update_role(self, workspace_id, role):
        return None


workspace_store = WorkspaceStore()


def update_workspace_role(request):
    workspace_store.update_role(
        request.session["workspace_id"],
        request.POST["role"],
    )
    return None


urlpatterns = [
    path("workspaces/current/role/", update_workspace_role),
]
