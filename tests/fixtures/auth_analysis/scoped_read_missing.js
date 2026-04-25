const express = require("express");
const router = express.Router();
const requireLogin = require("./auth").requireLogin;

router.get("/projects/:id", requireLogin, async (req, res) => {
    const project = await projectModel.findById(req.params.id);
    res.json({ project });
});
