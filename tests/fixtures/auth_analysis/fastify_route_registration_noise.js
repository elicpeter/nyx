const fastify = require("fastify")();
const requireAuth = require("./auth").requireAuth;

fastify.addHook("preHandler", requireAuth);
fastify.register(async function projectPlugin(instance) {
    instance.decorate("requireWorkspace", requireAuth);
});

fastify.route({
    method: "GET",
    url: "/me/projects",
    preHandler: requireAuth,
    handler: async function listProjects(request, reply) {
        const projects = await projectService.listForUser(request.user.id);
        reply.send({ projects });
    },
});

module.exports = { fastify };
