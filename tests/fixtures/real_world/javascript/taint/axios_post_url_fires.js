var express = require('express');
var axios = require('axios');
var app = express();

// Positive case: the URL argument is attacker-controlled.
// axios.post(taintedUrl, fixedPayload) — SSRF must fire on arg 0.
app.post('/proxy', function(req, res) {
    var target = req.query.target;
    axios.post(target, { event: 'ping' });
    res.status(204).end();
});
