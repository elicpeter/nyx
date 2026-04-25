var express = require('express');
var app = express();

app.get('/heap', function(req, res) {
    var a = [];
    var b = a;
    a.push(req.query.input);
    res.send(b.join(''));
});
