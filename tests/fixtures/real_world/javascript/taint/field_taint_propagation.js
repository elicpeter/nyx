var express = require('express');
var app = express();

app.get('/field', function(req, res) {
    var obj = {};
    obj.data = req.query.input;
    res.send(obj.data);
});
