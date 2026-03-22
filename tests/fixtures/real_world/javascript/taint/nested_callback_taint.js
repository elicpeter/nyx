var express = require('express');
var http = require('http');
var app = express();

app.post('/submit', function(req, res) {
    var data = req.body.payload;
    http.request('http://internal/' + data, function(apiRes) {
        var chunks = [];
        apiRes.on('data', function(chunk) {
            chunks.push(chunk);
        });
        apiRes.on('end', function() {
            res.send(chunks.join(''));
        });
    }).end();
});
