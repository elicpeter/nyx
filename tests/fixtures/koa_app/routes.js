const Koa = require("koa");
const Router = require("@koa/router");

const app = new Koa();
const router = new Router();

router.get("/echo", async (ctx) => {
    const input = ctx.query.data;
    ctx.body = input;
});

router.get("/go", async (ctx) => {
    ctx.redirect(ctx.query.next);
});

app.use(router.routes());
module.exports = { app, router };
