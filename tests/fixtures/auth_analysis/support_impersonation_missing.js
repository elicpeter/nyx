const express = require("express");
const router = express.Router();
const requireLogin = require("./auth").requireLogin;

router.post("/support/impersonate", requireLogin, async (req, res) => {
    await authService.startImpersonation(req, req.body.email);
    res.json({ ok: true });
});
