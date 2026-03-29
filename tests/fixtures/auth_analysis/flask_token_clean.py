def now():
    return 100


class InvitationStore:
    def find_by_token(self, token):
        return token


class WorkspaceStore:
    def add_membership(self, workspace_id, user_id, role):
        return None


invitation_store = InvitationStore()
workspace_store = WorkspaceStore()


def accept_invitation(token, current_user):
    invitation = invitation_store.find_by_token(token)
    if invitation.expires_at > now() and invitation.email == current_user.email:
        return workspace_store.add_membership(
            invitation.workspace_id,
            current_user.id,
            invitation.requested_role,
        )

    return None
