const express = require("express");
const router = express.Router();
const requireLogin = require("./auth").requireLogin;

router.get("/debug/session", requireLogin, async (req, res) => {
    res.json(adminService.buildDebugPayload(req));
});
