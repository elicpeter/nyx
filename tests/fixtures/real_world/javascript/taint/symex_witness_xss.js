var express = require('express');
var app = express();

app.get('/greet', function(req, res) {
    var name = req.query.name;
    var html = "<h1>Hello " + name + "</h1>";
    res.send(html);
});
