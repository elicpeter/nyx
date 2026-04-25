async function acceptInvitation(token, currentUser) {
    const invitation = await invitationModel.findByToken(token);
    if (invitation.email === currentUser.email) {
        return workspaceModel.addMembership(invitation.workspace_id, currentUser.id, invitation.requested_role);
    }
}

module.exports = { acceptInvitation };
