var child_process = require('child_process');
var express = require('express');
var app = express();

app.get('/ping', function(req, res) {
    var host = req.query.host;
    child_process.exec('ping -c 1 ' + host, function(err, stdout) {
        res.send(stdout);
    });
});

app.get('/safe-ping', function(req, res) {
    var host = req.query.host;
    var sanitized = host.replace(/[^a-zA-Z0-9.]/g, '');
    child_process.exec('ping -c 1 ' + sanitized, function(err, stdout) {
        res.send(stdout);
    });
});
