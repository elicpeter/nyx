var express = require('express');
var app = express();

app.get('/greet', function(req, res) {
    var name = req.query.name;
    res.send('<h1>Hello ' + name + '</h1>');
});
