const fastify = require("fastify")();
const requireLogin = require("./auth").requireLogin;
const requireAdmin = require("./auth").requireAdmin;

fastify.get("/admin/dashboard", {
    preHandler: [requireLogin, requireAdmin],
    handler: async function dashboard(request, reply) {
        reply.send(await adminService.getDashboard(request.user.id));
    },
});

module.exports = { fastify };
