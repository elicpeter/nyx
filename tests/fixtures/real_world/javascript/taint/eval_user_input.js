var express = require('express');
var app = express();

app.get('/calc', function(req, res) {
    var expr = req.query.expr;
    var result = eval(expr);
    res.json({ result: result });
});

app.get('/calc-safe', function(req, res) {
    var expr = req.query.expr;
    var num = parseFloat(expr);
    if (isNaN(num)) {
        return res.status(400).send('Invalid');
    }
    res.json({ result: num });
});
