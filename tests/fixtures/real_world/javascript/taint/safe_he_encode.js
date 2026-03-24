var express = require('express');
var he = require('he');
var app = express();

app.get('/greet', function(req, res) {
    var name = req.query.name;
    var safe = he.encode(name);
    res.send('<h1>Hello ' + safe + '</h1>');
});
