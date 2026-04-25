const express = require("express");
const router = express.Router();

router.get("/login", (req, res) => {
    res.render("login", { next: req.query.next || "" });
});

router.post("/logout", (req, res) => {
    req.session.destroy(() => res.redirect("/login"));
});
