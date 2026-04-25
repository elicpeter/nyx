const express = require("express");
const router = express.Router();
const requireLogin = require("./auth").requireLogin;

router.post("/jobs/run-digest", requireLogin, async (req, res) => {
    const digest = await digestService.runWorkspaceDigest(Number(req.body.workspaceId), req.body.kind);
    res.json({ digest });
});
