class InvitationManager:
    def get(self, **kwargs):
        return kwargs


class Invitation:
    objects = InvitationManager()


class WorkspaceStore:
    def add_membership(self, workspace_id, user_id, role):
        return None


workspace_store = WorkspaceStore()


def accept_invitation(request, token, role_override):
    invitation = Invitation.objects.get(token=token)
    if invitation.email == request.user.email:
        return workspace_store.add_membership(
            invitation.workspace_id,
            request.user.id,
            role_override or invitation.requested_role,
        )

    return None
