const express = require("express");
const router = express.Router();
const requireLogin = require("./auth").requireLogin;

router.get("/projects/:id", requireLogin, async (req, res) => {
    const data = await projectService.getProjectPageData(
        req.session.user.id,
        req.params.id,
    );
    res.json({ data });
});
