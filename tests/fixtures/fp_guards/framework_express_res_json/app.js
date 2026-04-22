// FP GUARD — framework-safe pattern (Express res.json with constant
// fields).
//
// res.json is a broad HTTP response sink but it is NOT itself an XSS
// sink (the browser parses the body as JSON, not HTML).  A precise
// analysis must not flag taint-unsanitised-flow on a res.json call
// whose payload is a constant object — even when the request object
// is in scope and commonly contains tainted values.
//
// Expected: NO taint-unsanitised-flow finding.

const express = require("express");
const app = express();

app.get("/healthz", (req, res) => {
    // The request is present but nothing tainted is extracted from
    // it.  The response body is a fixed literal.
    res.json({ status: "ok", uptimeSeconds: 0 });
});

module.exports = app;
