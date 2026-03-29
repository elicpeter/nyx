const Router = require("@koa/router");
const koaRouter = new Router();
const fastify = require("fastify")();
const requireLogin = require("./auth").requireLogin;

koaRouter.post("/admin/users/:id/role", requireLogin, async (ctx) => {
    await adminService.updateUserRole(ctx.params.id, ctx.request.body.role);
    ctx.body = { ok: true };
});

fastify.route({
    method: "POST",
    url: "/projects/:projectId/state",
    preValidation: requireLogin,
    handler: async function updateProjectState(request, reply) {
        const project = await projectModel.updateState(request.params.projectId, request.body);
        reply.send({ project });
    },
});

async function acceptInvitation(token, currentUser, roleOverride) {
    const invitation = await invitationModel.findByToken(token);
    if (Date.now() < invitation.expires_at && invitation.email === currentUser.email) {
        return workspaceModel.addMembership(
            invitation.workspace_id,
            currentUser.id,
            roleOverride || invitation.requested_role,
        );
    }
}

async function bulkArchive(userId, ids) {
    await checkMembership(userId, ids[0]);
    return projectModel.archiveByIds(ids);
}

module.exports = { koaRouter, fastify, acceptInvitation, bulkArchive };
