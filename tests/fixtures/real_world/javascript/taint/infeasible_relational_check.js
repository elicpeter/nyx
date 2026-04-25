var express = require('express');
var app = express();

app.get('/test', function(req, res) {
    var a = parseInt(req.query.a);
    var b = parseInt(req.query.b);
    var cmd = req.query.cmd;
    if (a < b) {
        if (b < a) {
            // Infeasible: a < b AND b < a
            eval(cmd);
        }
    }
    eval(cmd);
});
