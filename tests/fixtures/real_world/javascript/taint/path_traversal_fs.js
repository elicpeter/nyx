var express = require('express');
var fs = require('fs');
var path = require('path');
var app = express();

app.get('/read', function(req, res) {
    var filePath = req.query.path;
    var content = fs.readFileSync(filePath, 'utf8');
    res.send(content);
});

app.get('/read-safe', function(req, res) {
    var filePath = req.query.path;
    var resolved = path.resolve('/safe/dir', filePath);
    if (!resolved.startsWith('/safe/dir')) {
        return res.status(403).send('Forbidden');
    }
    var content = fs.readFileSync(resolved, 'utf8');
    res.send(content);
});
