async function getProjectArtifacts(userId, project) {
    const allowed = await hasWorkspaceMembership(userId, project.workspace_id);
    if (!allowed) {
        throw new Error("not allowed");
    }

    return noteModel.listByProject(project.id);
}

module.exports = { getProjectArtifacts };
