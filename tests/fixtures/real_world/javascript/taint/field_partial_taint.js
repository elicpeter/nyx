var express = require('express');
var app = express();

app.get('/partial', function(req, res) {
    var obj = {};
    obj.safe = "constant";
    obj.danger = req.query.input;
    res.send(obj);
});
