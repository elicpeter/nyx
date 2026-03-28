const express = require("express");
const router = express.Router();
const requireLogin = require("./auth").requireLogin;

router.get("/dashboard", requireLogin, async (req, res) => {
    const workspaces = await workspaceModel.listForUser(req.session.user.id);
    res.json({ workspaces });
});
