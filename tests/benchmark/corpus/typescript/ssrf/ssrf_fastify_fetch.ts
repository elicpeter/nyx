import Fastify, { FastifyRequest, FastifyReply } from 'fastify';

const fastify = Fastify();

interface FetchQuery { url: string }

fastify.get<{ Querystring: FetchQuery }>('/fetch', async (request: FastifyRequest<{ Querystring: FetchQuery }>, reply: FastifyReply) => {
    const target = request.query.url;
    const r = await fetch(target);
    const body = await r.text();
    reply.send(body);
});
