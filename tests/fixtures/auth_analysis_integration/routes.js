const express = require("express");
const router = express.Router();
const requireLogin = require("./auth").requireLogin;

router.post("/admin/users/:id/role", requireLogin, async (req, res) => {
    await adminService.updateUserRole(req.params.id, req.body.role);
    res.json({ ok: true });
});

router.post("/projects/:id/state", requireLogin, async (req, res) => {
    const project = await projectModel.updateState(req.params.id, req.body);
    res.json({ project });
});

async function acceptInvitation(token, currentUser, roleOverride) {
    const invitation = await invitationModel.findByToken(token);
    return workspaceModel.addMembership(
        invitation.workspace_id,
        currentUser.id,
        roleOverride || invitation.requested_role
    );
}

async function bulkArchive(userId, ids) {
    await checkMembership(userId, ids[0]);
    return projectModel.archiveByIds(ids);
}

module.exports = { router, acceptInvitation, bulkArchive };
