var express = require('express');
var app = express();

app.get('/profile', function(req, res) {
    var name = req.query.name;
    var safe = name.replace("<", "&lt;");
    res.send('<p>Hello ' + safe + '</p>');
});
