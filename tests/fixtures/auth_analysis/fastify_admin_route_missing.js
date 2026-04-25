const fastify = require("fastify")();
const requireLogin = require("./auth").requireLogin;

fastify.post(
    "/admin/users/:id/role",
    { preHandler: requireLogin },
    async function updateUserRole(request, reply) {
        await adminService.updateUserRole(request.params.id, request.body.role);
        reply.send({ ok: true });
    },
);

module.exports = { fastify };
