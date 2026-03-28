async function updateProject(projectId, payload, currentUser) {
    await checkOwnership(currentUser.id, projectId);
    return projectModel.updateProject(projectId, payload);
}

module.exports = { updateProject };
