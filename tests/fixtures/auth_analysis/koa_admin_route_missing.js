const Router = require("@koa/router");
const koaRouter = new Router();
const requireLogin = require("./auth").requireLogin;

koaRouter.post("/admin/users/:id/role", requireLogin, async (ctx) => {
    await adminService.updateUserRole(ctx.params.id, ctx.request.body.role);
    ctx.body = { ok: true };
});

module.exports = { koaRouter };
