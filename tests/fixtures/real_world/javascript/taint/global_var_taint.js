var express = require('express');
var app = express();
var lastInput = '';

app.get('/save', function(req, res) {
    lastInput = req.query.data;
    res.send('saved');
});

app.get('/display', function(req, res) {
    res.send('<p>' + lastInput + '</p>');
});
