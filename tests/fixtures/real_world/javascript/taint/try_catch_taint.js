var express = require('express');
var app = express();

app.get('/vulnerable', function(req, res) {
    var input = req.query.name;
    try {
        JSON.parse(input);
    } catch (e) {
        res.send('<h1>Error: ' + input + '</h1>');
    }
});

app.get('/safe', function(req, res) {
    var input = req.query.name;
    try {
        JSON.parse(input);
    } catch (e) {
        var clean = DOMPurify.sanitize(input);
        res.send('<h1>Error: ' + clean + '</h1>');
    }
});
