var express = require('express');
var child_process = require('child_process');
var app = express();

app.get('/lookup', function(req, res) {
    var domain = req.query.domain;
    var cmd = 'nslookup ' + domain;
    child_process.exec(cmd, function(err, stdout) {
        res.send(stdout);
    });
});
