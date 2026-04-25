var express = require('express');
var app = express();

app.get('/proxy', function(req, res) {
    var url = req.query.url;
    fetch(url).then(function(response) {
        return response.text();
    }).then(function(body) {
        res.send(body);
    });
});
