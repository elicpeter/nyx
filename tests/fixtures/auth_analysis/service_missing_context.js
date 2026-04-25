async function updateProject(projectId, payload) {
    return projectModel.updateProject(projectId, payload);
}

module.exports = { updateProject };
