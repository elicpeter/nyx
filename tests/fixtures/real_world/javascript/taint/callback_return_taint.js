var express = require('express');
var app = express();
var fs = require('fs');

app.get('/read', function(req, res) {
    var filename = req.query.file;
    fs.readFile(filename, function(err, data) {
        res.send(data);
    });
});
