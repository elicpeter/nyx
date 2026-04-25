const express = require("express");
const router = express.Router();
const requireLogin = require("./auth").requireLogin;

router.post("/projects/:id/state", requireLogin, async (req, res) => {
    const project = await projectModel.updateState(req.params.id, req.body);
    res.json({ project });
});
