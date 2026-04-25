const Router = require("@koa/router");
const koaRouter = new Router();
const requireAdmin = require("./auth").requireAdmin;

koaRouter.get("/admin/dashboard", requireAdmin, async (ctx) => {
    ctx.body = await adminService.getDashboard(ctx.state.user.id);
});

module.exports = { koaRouter };
