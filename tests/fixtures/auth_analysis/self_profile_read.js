const express = require("express");
const router = express.Router();
const requireLogin = require("./auth").requireLogin;

router.get("/profile", requireLogin, async (req, res) => {
    const user = await userModel.findById(req.session.user.id);
    res.json({ user });
});
