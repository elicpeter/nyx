var express = require('express');
var app = express();

app.get('/data', function(req, res) {
    var id = req.query.id;
    fetch('/api/' + id).then(function(response) {
        return response.json();
    }).then(function(data) {
        res.send('<div>' + data.name + '</div>');
    });
});
