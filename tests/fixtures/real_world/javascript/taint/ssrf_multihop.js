var express = require('express');
var app = express();

app.get('/proxy', function(req, res) {
    var input = req.query.target;
    var baseUrl = 'https://' + input;
    var endpoint = baseUrl + '/api';
    fetch(endpoint).then(function(response) {
        return response.text();
    }).then(function(body) {
        res.send(body);
    });
});
