const Router = require("@koa/router");
const koaRouter = new Router();
const fastify = require("fastify")();
const requireLogin = require("./auth").requireLogin;
const requireAuth = require("./auth").requireAuth;

koaRouter.use(requireLogin);
koaRouter.get("/profile", requireLogin, async (ctx) => {
    const user = await userModel.findById(ctx.state.user.id);
    ctx.body = { user };
});

fastify.addHook("preHandler", requireAuth);
fastify.route({
    method: "GET",
    url: "/me/projects",
    preHandler: requireAuth,
    handler: async function listProjects(request, reply) {
        const projects = await projectService.listForUser(request.user.id);
        reply.send({ projects });
    },
});

module.exports = { koaRouter, fastify };
