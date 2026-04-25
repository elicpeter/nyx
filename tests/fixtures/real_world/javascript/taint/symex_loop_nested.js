var express = require('express');
var app = express();

app.get('/matrix', function(req, res) {
    var data = req.query.payload;
    var out = data;
    for (var i = 0; i < 3; i++) {
        for (var j = 0; j < 3; j++) {
            out = out + ".";
        }
    }
    eval(out);
});
