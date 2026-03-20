var express = require('express');
var app = express();

app.get('/go', function(req, res) {
    var url = req.query.url;
    res.redirect(url);
});

app.get('/go-encoded', function(req, res) {
    var url = req.query.url;
    var encoded = encodeURIComponent(url);
    res.redirect(encoded);
});
