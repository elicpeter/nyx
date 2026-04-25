var express = require('express');
var app = express();

app.get('/search', function(req, res) {
    var q = req.query.q;
    var page = req.query.page;
    var result = '<p>Search: ' + q + ' Page: ' + page + '</p>';
    res.send(result);
});
