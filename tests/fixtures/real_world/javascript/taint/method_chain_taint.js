var express = require('express');
var app = express();

app.get('/api', function(req, res) {
    var input = req.query.search;
    var result = input.trim().toLowerCase();
    res.send('<p>' + result + '</p>');
});
