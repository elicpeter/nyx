const Router = require("@koa/router");
const koaRouter = new Router();
const requireLogin = require("./auth").requireLogin;

koaRouter.use(requireLogin);
koaRouter.use("/workspace", requireLogin);

koaRouter.get("/profile", requireLogin, async (ctx) => {
    const user = await userModel.findById(ctx.state.user.id);
    ctx.body = { user };
});

module.exports = { koaRouter };
