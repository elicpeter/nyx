var express = require('express');
var app = express();

app.get('/items', function(req, res) {
    var data = req.query.input;
    for (var i = 0; i < 3; i++) {
        eval(data);
    }
});
