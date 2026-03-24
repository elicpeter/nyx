var express = require('express');
var app = express();

app.get('/api/user', function(req, res) {
    var userId = req.query.id;
    var url = 'https://api.internal.example.com/users/' + userId;
    fetch(url).then(function(response) {
        res.json(response);
    });
});
