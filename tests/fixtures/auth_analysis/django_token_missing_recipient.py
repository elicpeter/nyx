class InvitationManager:
    def get(self, **kwargs):
        return kwargs


class Invitation:
    objects = InvitationManager()


class WorkspaceStore:
    def add_membership(self, workspace_id, user_id, role):
        return None


def now():
    return 100


workspace_store = WorkspaceStore()


def accept_invitation(token, current_user):
    invitation = Invitation.objects.get(token=token)
    if invitation.expires_at > now():
        return workspace_store.add_membership(
            invitation.workspace_id,
            current_user.id,
            invitation.requested_role,
        )

    return None
