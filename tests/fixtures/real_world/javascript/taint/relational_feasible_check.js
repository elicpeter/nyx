var express = require('express');
var app = express();

app.get('/test', function(req, res) {
    var a = parseInt(req.query.a);
    var b = parseInt(req.query.b);
    var cmd = req.query.cmd;
    if (a < b) {
        if (a < 100) {
            // Feasible: a < b and a < 100 are compatible
            eval(cmd);
        }
    }
});
