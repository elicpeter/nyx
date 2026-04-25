const Router = require("@koa/router");
const router = new Router();
const fastify = require("fastify")();

router.get("/health", async (ctx) => {
    ctx.body = { ok: true };
});

router.use(async (ctx, next) => {
    await next();
});

fastify.addHook("preHandler", async function noOp(request, reply) {
    reply.header("x-trace", "static");
});

fastify.get("/ready", async function ready(request, reply) {
    reply.send({ ok: true });
});

module.exports = { router, fastify };
