var express = require('express');
var app = express();

app.get('/data', function(req, res) {
    var input = req.query.name;
    var acc = input;
    for (var i = 0; i < 5; i++) {
        acc = acc + String(i);
    }
    res.send("<h1>" + acc + "</h1>");
});
