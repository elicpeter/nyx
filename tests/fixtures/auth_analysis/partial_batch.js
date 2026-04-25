async function bulkArchive(userId, ids) {
    await checkMembership(userId, ids[0]);
    return projectModel.archiveByIds(ids);
}

module.exports = { bulkArchive };
