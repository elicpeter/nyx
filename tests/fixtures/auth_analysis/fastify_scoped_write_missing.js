const fastify = require("fastify")();
const requireAuth = require("./auth").requireAuth;

fastify.route({
    method: "POST",
    url: "/projects/:projectId/state",
    preValidation: requireAuth,
    handler: updateProjectState,
});

async function updateProjectState(request, reply) {
    const project = await projectModel.updateState(request.params.projectId, request.body);
    reply.send({ project });
}

module.exports = { fastify, updateProjectState };
