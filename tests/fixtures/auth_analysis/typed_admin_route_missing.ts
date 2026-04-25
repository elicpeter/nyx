const express = require("express");
const router = express.Router();
const requireLogin = require("./auth").requireLogin;

router.post("/admin/projects/:id/archive", requireLogin, async (req, res) => {
    await adminAuditService.publish(req.params.id);
    res.json({ ok: true });
});
