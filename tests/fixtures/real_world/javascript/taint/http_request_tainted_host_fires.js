var express = require('express');
var http = require('http');
var app = express();

// http.request(options, cb) — options.host / options.hostname / options.path
// are destination-bearing fields. Attacker-controlled host must fire SSRF.
app.get('/proxy', function(req, res) {
    var target = req.query.host;
    var options = {
        host: target,
        path: '/status',
        method: 'GET',
    };
    var r = http.request(options);
    r.end();
    res.status(204).end();
});
