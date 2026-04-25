var express = require('express');
var app = express();

app.get('/api', function(req, res) {
    var x = req.query.input;
    var y = x;
    var z = y;
    eval(z);
});
