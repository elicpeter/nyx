var express = require('express');
var got = require('got');
var app = express();

// got({url: taintedUrl, ...}) — attacker controls the destination field.
app.get('/proxy', function(req, res) {
    var target = req.query.target;
    got({
        url: target,
        headers: { 'User-Agent': 'nyx-test' },
    });
    res.status(204).end();
});
