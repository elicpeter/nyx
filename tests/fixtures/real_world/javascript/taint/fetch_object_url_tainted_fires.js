var express = require('express');
var app = express();

// Positive case: fetch accepts a Request-like object whose `url`
// field carries the destination. When `url` is attacker-controlled, SSRF
// must fire even though `body` (non-destination) is fixed.
app.get('/proxy', function(req, res) {
    var target = req.query.target;
    fetch({
        url: target,
        method: 'POST',
        body: '{}',
    });
    res.status(204).end();
});
