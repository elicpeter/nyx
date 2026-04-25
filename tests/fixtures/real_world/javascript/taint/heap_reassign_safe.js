var express = require('express');
var app = express();

app.get('/reassign', function(req, res) {
    var a = [];
    var b = a;
    a = [];
    b.push(req.query.input);
    res.send(a.join(''));
});
