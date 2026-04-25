const { safeRedirect } = require('./helper');

/**
 * VULN: req.body.returnTo (user input) flows through safeRedirect() — a
 * cross-file passthrough — directly into res.redirect() (SSRF sink).
 * The source member expression is inline in the call argument, exercising
 * source node pre-emission for inline source arguments.
 */
function handleLogin(req, res) {
    res.redirect(safeRedirect(req.body.returnTo, "/dashboard"));
}
