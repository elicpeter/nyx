const express = require("express");
const router = express.Router();
const requireLogin = require("./auth").requireLogin;

router.post("/profile", requireLogin, async (req, res) => {
    await userModel.updateProfile(req.session.user.id, {
        bio: req.body.bio,
        themeConfig: req.body.themeConfig,
    });
    res.json({ ok: true });
});
