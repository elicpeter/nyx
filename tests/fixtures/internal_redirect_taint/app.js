const express = require("express");
const router = express.Router();

// Should NOT fire -- internal path-prefix redirect
router.post("/projects/:id", (req, res) => {
    res.redirect(`/projects/${req.params.id}`);
});

// Should NOT fire -- internal path-prefix redirect
router.post("/workspaces/:id", (req, res) => {
    res.redirect(`/workspaces/${req.params.id}`);
});

// SHOULD fire -- user controls full redirect target
router.get("/go", (req, res) => {
    res.redirect(req.query.next);
});
