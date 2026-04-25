var express = require('express');
var app = express();

app.get('/proxy', function(req, res) {
    var target = req.query.host;
    var url = 'https://' + target;
    fetch(url).then(function(response) {
        res.json(response);
    });
});
