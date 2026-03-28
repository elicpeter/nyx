async function hasWorkspaceMembership(userId, workspaceId) {
    const memberships = await workspaceModel.listForUser(userId);
    return memberships.some((workspace) => workspace.id === Number(workspaceId));
}

module.exports = { hasWorkspaceMembership };
