var express = require('express');
var app = express();

// Regression for the dominant SSRF FP observed in production: request-body
// content (user-controlled via an explicit source) flowing into a telemetry
// POST body with a fixed submit URL. Destination is not attacker-controlled;
// only body is. Must not fire SSRF after the destination-aware gate narrowing.
app.post('/bugreport', function(req, res) {
    var details = req.body.details;
    fetch('https://telemetry.example.com/bug', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: details,
    });
    res.status(204).end();
});
