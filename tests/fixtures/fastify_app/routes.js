const fastify = require("fastify")();

fastify.get("/echo", async function echo(request, reply) {
    reply.send(request.query.data);
});

fastify.get("/go", async function go(request, reply) {
    return reply.redirect(request.query.next);
});

module.exports = { fastify };
