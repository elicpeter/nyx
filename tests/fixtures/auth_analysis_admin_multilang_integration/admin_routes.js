const express = require("express");
const router = express.Router();
const requireLogin = require("./auth").requireLogin;

router.post("/admin/projects/archive", requireLogin, async (req, res) => {
    await adminAuditService.publish();
    res.json({ ok: true });
});
