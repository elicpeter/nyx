var express = require('express');
var app = express();

// Taint flows into the fetch *body* (telemetry payload) with a fixed,
// attacker-independent URL. SSRF semantics require attacker control over
// the destination — a tainted body does not constitute SSRF. Nyx must
// silence this case after the fetch-as-destination-gate narrowing.
app.post('/telemetry', function(req, res) {
    var payload = req.body.message;
    fetch('/api/telemetry', {
        method: 'POST',
        body: payload,
    });
    res.status(204).end();
});
