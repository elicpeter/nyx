var express = require('express');
var got = require('got');
var app = express();

app.get('/proxy', function(req, res) {
    var url = req.query.url;
    got(url).then(function(response) {
        res.send(response.body);
    });
});
