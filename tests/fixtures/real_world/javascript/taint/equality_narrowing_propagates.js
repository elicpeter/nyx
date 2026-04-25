var express = require('express');
var app = express();

app.get('/display', function(req, res) {
    var input = req.query.name;
    var isAdmin = input === 'admin';
    res.send('<p>' + input + '</p>');
});
