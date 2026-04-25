async function bulkArchiveProjects(userId, ids) {
    await checkMembership(userId, ids);
    await checkMembership(userId, ids[0]);
    return projectModel.archiveByIds(ids);
}
