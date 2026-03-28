const express = require("express");
const router = express.Router();
const requireAdmin = require("./auth").requireAdmin;

router.get("/admin/dashboard", requireAdmin, async (req, res) => {
    res.render("admin/dashboard");
});
