const Router = require("@koa/router");
const koaRouter = new Router();
const requireLogin = require("./auth").requireLogin;

koaRouter.get("/projects/:projectId", requireLogin, getProject);

async function getProject(ctx) {
    const project = await projectModel.findById(ctx.params.projectId);
    ctx.body = { project };
}

module.exports = { koaRouter, getProject };
