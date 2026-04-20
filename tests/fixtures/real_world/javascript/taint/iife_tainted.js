// Immediately-invoked function expression — arrow gets called inline.
var express = require('express');
var app = express();

app.get('/a', function(req, res) {
    var q = req.query.q;
    (function(arg) { eval(arg); })(q);   // IIFE consuming tainted arg
    res.send('ok');
});
