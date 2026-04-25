var express = require('express');
var app = express();

app.get('/field-safe', function(req, res) {
    var obj = req.query;
    obj.safe = "constant";
    res.send(obj.safe);
});
