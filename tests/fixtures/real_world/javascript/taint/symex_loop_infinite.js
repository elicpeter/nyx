var express = require('express');
var app = express();

app.get('/stream', function(req, res) {
    var cmd = req.query.cmd;
    while (true) {
        eval(cmd);
        if (Math.random() > 0.5) {
            break;
        }
    }
});
