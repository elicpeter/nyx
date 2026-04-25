var express = require('express');
var app = express();
var child_process = require('child_process');

app.get('/run', function(req, res) {
    var cmd = req.query.cmd;
    child_process.exec("ls " + cmd);
});
