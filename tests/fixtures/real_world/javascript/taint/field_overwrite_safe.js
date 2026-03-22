var express = require('express');
var app = express();

app.get('/safe', function(req, res) {
    var obj = {};
    obj.data = req.query.input;
    obj.data = "safe";
    res.send(obj.data);
});
