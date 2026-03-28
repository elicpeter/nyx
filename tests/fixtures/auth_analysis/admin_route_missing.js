const express = require("express");
const router = express.Router();
const requireLogin = require("./auth").requireLogin;

router.post("/admin/users/:id/role", requireLogin, async (req, res) => {
    await adminService.updateUserRole(req.params.id, req.body.role);
    res.json({ ok: true });
});
