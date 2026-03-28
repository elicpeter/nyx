async function acceptInvitation(token, currentUser, requestedWorkspaceId) {
    const invitation = await invitationModel.findByToken(token);
    if (Date.now() < invitation.expires_at && invitation.email === currentUser.email) {
        return workspaceModel.addMembership(requestedWorkspaceId || invitation.workspace_id, currentUser.id, invitation.requested_role);
    }
}

module.exports = { acceptInvitation };
