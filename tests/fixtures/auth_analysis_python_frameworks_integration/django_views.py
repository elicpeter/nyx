from django.urls import path


class View:
    @classmethod
    def as_view(cls):
        return cls


class ProjectStore:
    def archive(self, ids):
        return None


class WorkspaceStore:
    def update_role(self, workspace_id, role):
        return None

    def add_membership(self, workspace_id, user_id, role):
        return None


class InvitationManager:
    def get(self, **kwargs):
        return kwargs


class Invitation:
    objects = InvitationManager()


project_store = ProjectStore()
workspace_store = WorkspaceStore()


def check_membership(user_id, project_id):
    return True


def bulk_archive(request):
    ids = request.POST["ids"]
    check_membership(request.user.id, ids[0])
    project_store.archive(ids)
    return None


def update_workspace_role(request):
    workspace_store.update_role(
        request.session["workspace_id"],
        request.POST["role"],
    )
    return None


def accept_invitation(request, token, role_override):
    invitation = Invitation.objects.get(token=token)
    if invitation.email == request.user.email:
        return workspace_store.add_membership(
            invitation.workspace_id,
            request.user.id,
            role_override or invitation.requested_role,
        )

    return None


urlpatterns = [
    path("projects/archive/", bulk_archive),
    path("workspaces/current/role/", update_workspace_role),
    path("invitations/accept/<slug:token>/", accept_invitation),
]
