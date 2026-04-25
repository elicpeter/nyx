const fastify = require("fastify")();
const requireAuth = require("./auth").requireAuth;

fastify.route({
    method: "POST",
    url: "/projects/:projectId/state",
    onRequest: requireAuth,
    handler: updateProjectState,
});

async function updateProjectState(request, reply) {
    const allowed = await checkOwnership(request.user.id, request.params.projectId);
    if (!allowed) {
        reply.code(403).send({ error: "forbidden" });
        return;
    }

    const project = await projectModel.updateState(request.params.projectId, request.body);
    reply.send({ project });
}

module.exports = { fastify, updateProjectState };
