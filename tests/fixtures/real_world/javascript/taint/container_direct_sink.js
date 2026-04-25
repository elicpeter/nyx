var express = require('express');
var child_process = require('child_process');
var app = express();

app.get('/direct', function(req, res) {
    var commands = [];
    commands.push(req.query.cmd);
    child_process.exec(commands.join(' '));
});
