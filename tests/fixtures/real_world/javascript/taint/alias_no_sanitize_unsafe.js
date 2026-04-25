var express = require('express');
var app = express();

app.get('/unsafe', function(req, res) {
    var obj = {};
    obj.data = req.query.input;
    var alias = obj;
    res.send(alias.data);
});
