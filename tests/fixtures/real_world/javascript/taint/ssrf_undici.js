var express = require('express');
var undici = require('undici');
var app = express();

app.get('/proxy', function(req, res) {
    var url = req.query.url;
    undici.request(url).then(function(response) {
        res.send(response.body);
    });
});
