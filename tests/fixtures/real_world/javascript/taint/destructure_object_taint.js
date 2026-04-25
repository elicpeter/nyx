var express = require('express');
var app = express();

app.get('/destruct', function(req, res) {
    var { name, age } = req.query;
    res.send(name);
});
