var express = require('express');
var app = express();

app.get('/api', function(req, res) {
    var data = req.query.input;
    var result = data;
    for (var i = 0; i < 10; i++) {
        result = result + "x";
    }
    eval(result);
});
