var express = require('express');
var app = express();

app.get('/user', function(req, res) {
    var id = req.query.id;
    var sanitized = parseInt(id, 10);
    if (isNaN(sanitized)) {
        return res.status(400).send('Invalid');
    }
    res.send('User: ' + sanitized);
});
