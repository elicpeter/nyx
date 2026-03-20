var express = require('express');
var app = express();

var ALLOWED_HOSTS = ['api.example.com', 'cdn.example.com'];

app.get('/proxy', function(req, res) {
    var url = req.query.url;
    var parsed = new URL(url);
    if (ALLOWED_HOSTS.indexOf(parsed.hostname) === -1) {
        return res.status(403).send('Forbidden');
    }
    fetch('https://' + parsed.hostname + parsed.pathname).then(function(response) {
        return response.text();
    }).then(function(body) {
        res.send(body);
    });
});
