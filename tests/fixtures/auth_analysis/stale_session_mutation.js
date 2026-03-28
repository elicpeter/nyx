async function confirmPublish(req) {
    return projectModel.updateState(req.session.publishProjectId, {
        visibility: "public",
    });
}

module.exports = { confirmPublish };
